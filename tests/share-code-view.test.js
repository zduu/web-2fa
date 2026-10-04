import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { startCodeShareView } from "../src/share/code-view.js";

let elements;
let fetchMock;
let disposers;

function response(code = "123456", { remaining = "unlimited", validForMs = 2000 } = {}) {
  return new Response(JSON.stringify({ code, validForMs, secondsLeft: validForMs / 1000,
    digits: 6, period: 30, algorithm: "SHA1", label: "Test" }), {
    headers: { "X-Access-Remaining": remaining },
  });
}

function start() {
  disposers.push(startCodeShareView("test-id", "test-code-key"));
}

beforeEach(() => {
  vi.useFakeTimers();
  elements = new Map();
  for (const name of ["lbl", "code", "note", "algo", "period-info", "secret-panel", "secret-value", ".left", ".bar", ".share-head .sub"]) {
    elements.set(name, { textContent: "", style: {}, value: "old-secret" });
  }
  const doc = new EventTarget();
  doc.visibilityState = "visible";
  doc.getElementById = (id) => elements.get(id);
  doc.querySelector = (selector) => elements.get(selector);
  vi.stubGlobal("document", doc);
  vi.stubGlobal("window", new EventTarget());
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
  disposers = [];
});

afterEach(() => {
  for (const dispose of disposers) dispose();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("safe share view", () => {
  it("fetches the next code at expiry and keeps the Secret hidden", async () => {
    fetchMock.mockResolvedValueOnce(response()).mockResolvedValueOnce(response("654321"));
    start();
    await vi.advanceTimersByTimeAsync(0);
    expect(elements.get("code").textContent.replace(/\s/g, "")).toBe("123456");
    expect(elements.get("secret-panel").style.display).toBe("none");
    expect(elements.get("secret-value").value).toBe("");
    await vi.advanceTimersByTimeAsync(2000);
    expect(elements.get("code").textContent.replace(/\s/g, "")).toBe("654321");
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock).toHaveBeenCalledWith("/api/share-code/test-id", expect.objectContaining({
      headers: { "X-Share-Code-Key": "test-code-key" }, cache: "no-store",
    }));
  });

  it.each([404, 410])("clears the old code and stops polling on %s", async (status) => {
    fetchMock.mockResolvedValueOnce(response()).mockResolvedValueOnce(new Response("Gone", { status }));
    start();
    await vi.advanceTimersByTimeAsync(12_000);
    expect(elements.get("code").textContent).toBe("已失效");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("keeps the final permitted code until expiry without another request", async () => {
    fetchMock.mockResolvedValueOnce(response("123456", { remaining: "0" }));
    start();
    await vi.advanceTimersByTimeAsync(0);
    expect(elements.get("code").textContent.replace(/\s/g, "")).toBe("123456");
    await vi.advanceTimersByTimeAsync(12_000);
    expect(elements.get("code").textContent).toBe("已过期");
    expect(elements.get("lbl").textContent).toBe("分享已达访问上限");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("retries a temporary network failure without leaving an expired code visible", async () => {
    fetchMock.mockResolvedValueOnce(response())
      .mockRejectedValueOnce(new Error("offline"))
      .mockResolvedValueOnce(response("654321"));
    start();
    await vi.advanceTimersByTimeAsync(2000);
    expect(elements.get("code").textContent).toBe("正在重试…");
    await vi.advanceTimersByTimeAsync(5000);
    expect(elements.get("code").textContent.replace(/\s/g, "")).toBe("654321");
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("pauses requests in a hidden tab and refreshes on return", async () => {
    fetchMock.mockResolvedValueOnce(response()).mockResolvedValueOnce(response("654321"));
    start();
    await vi.advanceTimersByTimeAsync(0);
    document.visibilityState = "hidden";
    await vi.advanceTimersByTimeAsync(10_000);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(elements.get("code").textContent).toBe("刷新中…");
    document.visibilityState = "visible";
    document.dispatchEvent(new Event("visibilitychange"));
    await vi.advanceTimersByTimeAsync(0);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(elements.get("code").textContent.replace(/\s/g, "")).toBe("654321");
  });

  it("does not overlap slow requests or extend code validity by network delay", async () => {
    let resolve;
    fetchMock.mockReturnValueOnce(new Promise((done) => { resolve = done; }))
      .mockResolvedValueOnce(response("654321"));
    start();
    await vi.advanceTimersByTimeAsync(4000);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    resolve(response("123456", { validForMs: 5000 }));
    await vi.advanceTimersByTimeAsync(0);
    expect(elements.get(".left").textContent).toBe("1");
    await vi.advanceTimersByTimeAsync(1000);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("aborts a hung request and retries after the timeout", async () => {
    fetchMock.mockImplementationOnce((_url, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener("abort", () => reject(new Error("aborted")));
    })).mockResolvedValueOnce(response("654321"));
    start();
    await vi.advanceTimersByTimeAsync(15_000);
    expect(elements.get("code").textContent).toBe("正在重试…");
    await vi.advanceTimersByTimeAsync(5000);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(elements.get("code").textContent.replace(/\s/g, "")).toBe("654321");
  });

  it("does not retry an exhausted share if its last code arrived too late", async () => {
    let resolve;
    fetchMock.mockReturnValueOnce(new Promise((done) => { resolve = done; }));
    start();
    await vi.advanceTimersByTimeAsync(3000);
    resolve(response("123456", { remaining: "0", validForMs: 2000 }));
    await vi.advanceTimersByTimeAsync(12_000);
    expect(elements.get("code").textContent).toBe("已过期");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("ignores a response received after the view is disposed", async () => {
    let resolve;
    fetchMock.mockReturnValueOnce(new Promise((done) => { resolve = done; }));
    start();
    disposers[0]();
    resolve(response());
    await vi.advanceTimersByTimeAsync(10_000);
    expect(elements.get("code").textContent).toBe("");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
