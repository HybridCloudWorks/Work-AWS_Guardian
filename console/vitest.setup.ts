import "@testing-library/dom";
import { afterEach, vi } from "vitest";

// Keep global fetch mocks from leaking across tests.
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
