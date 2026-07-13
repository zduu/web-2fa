import { afterEach, describe, expect, it, vi } from "vitest";

import { copyText, downloadBlob, escapeHtml, sanitizeFilePart, toast } from "../src/ui/toast.js";

const originalUrlDescriptor = Object.getOwnPropertyDescriptor(globalThis, "URL");

afterEach(() => {
  delete globalThis.document;
  delete globalThis.navigator;
  delete globalThis.window;
  if (originalUrlDescriptor) {
    Object.defineProperty(globalThis, "URL", originalUrlDescriptor);
  } else {
    delete globalThis.URL;
  }
  vi.restoreAllMocks();
});

describe("toast utilities", () => {
  it("treats toast display as unavailable without a DOM", () => {
    delete globalThis.document;

    expect(toast("hello")).toBe(false);
  });

  it("does not create a toast when document body is unavailable", () => {
    Object.defineProperty(globalThis, "document", {
      configurable: true,
      value: {
        createElement: vi.fn(),
      },
    });

    expect(toast("hello")).toBe(false);
    expect(globalThis.document.createElement).not.toHaveBeenCalled();
  });

  it("escapes HTML without requiring a DOM", () => {
    delete globalThis.document;

    expect(escapeHtml(`<tag attr="x">'&</tag>`)).toBe("&lt;tag attr=&quot;x&quot;&gt;&#39;&amp;&lt;/tag&gt;");
  });

  it("escapes quotes identically when a browser DOM is present", () => {
    Object.defineProperty(globalThis, "document", {
      configurable: true,
      value: { createElement: vi.fn() },
    });

    expect(escapeHtml(`x" onfocus="alert(1)'`)).toBe("x&quot; onfocus=&quot;alert(1)&#39;");
    expect(globalThis.document.createElement).not.toHaveBeenCalled();
  });

  it("copies text through the async clipboard API in secure contexts", async () => {
    const writeText = vi.fn(async () => {});
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { clipboard: { writeText } },
    });
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: { isSecureContext: true },
    });

    await expect(copyText(123)).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith("123");
  });

  it("returns false when no clipboard or DOM fallback is available", async () => {
    delete globalThis.navigator;
    delete globalThis.window;
    delete globalThis.document;

    await expect(copyText("secret")).resolves.toBe(false);
  });

  it("cleans up fallback textarea when legacy copy fails", async () => {
    const appended = [];
    const textarea = {
      style: {},
      setAttribute: vi.fn(),
      focus: vi.fn(),
      select: vi.fn(),
      setSelectionRange: vi.fn(),
      parentNode: {
        removeChild: vi.fn((node) => {
          const index = appended.indexOf(node);
          if (index >= 0) appended.splice(index, 1);
        }),
      },
    };
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {},
    });
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: { isSecureContext: false },
    });
    Object.defineProperty(globalThis, "document", {
      configurable: true,
      value: {
        createElement: vi.fn(() => textarea),
        body: {
          appendChild: vi.fn((node) => { appended.push(node); }),
        },
        execCommand: vi.fn(() => { throw new Error("copy blocked"); }),
      },
    });

    await expect(copyText("secret")).resolves.toBe(false);
    expect(textarea.parentNode.removeChild).toHaveBeenCalledWith(textarea);
    expect(appended).toEqual([]);
  });

  it("returns false for downloads without DOM support", () => {
    delete globalThis.document;

    expect(downloadBlob("demo.txt", new Blob(["demo"]))).toBe(false);
  });

  it("revokes download object URLs even when link clicks fail", () => {
    const revokeObjectURL = vi.fn();
    const createObjectURL = vi.fn(() => "blob:demo");
    Object.defineProperty(globalThis, "URL", {
      configurable: true,
      value: { createObjectURL, revokeObjectURL },
    });
    Object.defineProperty(globalThis, "document", {
      configurable: true,
      value: {
        createElement: vi.fn(() => ({
          click: vi.fn(() => { throw new Error("blocked"); }),
        })),
      },
    });

    expect(downloadBlob("demo.txt", new Blob(["demo"]))).toBe(false);
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:demo");
  });

  it("sanitizes file-name parts to a bounded portable subset", () => {
    expect(sanitizeFilePart(" Ops/Root, Team ")).toBe("_Ops_Root_Team_");
    expect(sanitizeFilePart("")).toBe("part");
    expect(sanitizeFilePart("////")).toBe("part");
    expect(sanitizeFilePart("..")).toBe("part");
    expect(sanitizeFilePart("a".repeat(80))).toHaveLength(64);
  });
});
