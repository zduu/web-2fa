import { describe, expect, it } from "vitest";

import {
  escapeModalHtml,
  getModalPreviousFocus,
  normalizeActionSheetIndex,
  normalizePromptInputType,
} from "../src/ui/modal.js";

describe("normalizeActionSheetIndex", () => {
  it("accepts only finite indices within the actions array", () => {
    expect(normalizeActionSheetIndex("0", 3)).toBe(0);
    expect(normalizeActionSheetIndex("2.9", 3)).toBe(2);
    expect(normalizeActionSheetIndex(3, 3)).toBe(-1);
    expect(normalizeActionSheetIndex(-1, 3)).toBe(-1);
    expect(normalizeActionSheetIndex("bad", 3)).toBe(-1);
    expect(normalizeActionSheetIndex("1e999", 3)).toBe(-1);
    expect(normalizeActionSheetIndex(0, 0)).toBe(-1);
    expect(normalizeActionSheetIndex(0, "bad")).toBe(-1);
  });
});

describe("normalizePromptInputType", () => {
  it("allows only known input types for prompt dialogs", () => {
    expect(normalizePromptInputType("password")).toBe("password");
    expect(normalizePromptInputType(" EMAIL ")).toBe("email");
    expect(normalizePromptInputType("number")).toBe("number");
    expect(normalizePromptInputType("search")).toBe("search");
    expect(normalizePromptInputType("tel")).toBe("tel");
    expect(normalizePromptInputType("url")).toBe("url");
    expect(normalizePromptInputType("")).toBe("text");
    expect(normalizePromptInputType(null)).toBe("text");
    expect(normalizePromptInputType("text\" autofocus")).toBe("text");
    expect(normalizePromptInputType("file")).toBe("text");
  });
});

describe("getModalPreviousFocus", () => {
  it("returns null when HTMLElement is unavailable", () => {
    expect(getModalPreviousFocus({ focus: () => {} }, undefined)).toBeNull();
  });

  it("keeps only elements created by the current element constructor", () => {
    class ElementMock {}
    const element = new ElementMock();

    expect(getModalPreviousFocus(element, ElementMock)).toBe(element);
    expect(getModalPreviousFocus({ focus: () => {} }, ElementMock)).toBeNull();
  });
});

describe("escapeModalHtml", () => {
  it("escapes modal text without requiring a document", () => {
    expect(escapeModalHtml(`<button title="x">Tom & 'Jerry'</button>`))
      .toBe("&lt;button title=&quot;x&quot;&gt;Tom &amp; &#39;Jerry&#39;&lt;/button&gt;");
    expect(escapeModalHtml(null)).toBe("");
  });
});
