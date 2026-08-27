import { describe, expect, it, vi } from "vitest";
import { createWindowChromePort, type NativeWindowControlState } from "../window-chrome";

describe("WindowChromePort", () => {
  it("browser preview is a no-op", async () => { await expect(createWindowChromePort({ browserPreview: true }).setMode("minimal")).resolves.toBeUndefined(); });
  it("forwards mode command in Tauri", async () => { const invoke = vi.fn(async () => undefined); await createWindowChromePort({ invoke }).setMode("advanced"); expect(invoke).toHaveBeenCalledWith("window_chrome_set_mode", { mode: "advanced" }); });
  it("forwards native window control commands in Tauri", async () => { const invoke = vi.fn(async () => undefined); await createWindowChromePort({ invoke }).control("minimize"); expect(invoke).toHaveBeenCalledWith("window_chrome_control", { control: "minimize" }); });
  it("browser preview does not invoke native window controls", async () => { const invoke = vi.fn(async () => undefined); await createWindowChromePort({ browserPreview: true, invoke }).control("close"); expect(invoke).not.toHaveBeenCalled(); });

  it("forwards native control state to a subscriber", async () => {
    let dispatch: ((event: { payload: NativeWindowControlState }) => void) | undefined;
    const port = createWindowChromePort({
      browserPreview: false,
      listen: async (_name, callback) => {
        dispatch = callback;
        return () => { dispatch = undefined; };
      },
    });
    const received: NativeWindowControlState[] = [];
    const dispose = await port.subscribeControlState((state) => received.push(state));

    dispatch?.({ payload: { control: "close", pressed: true } });

    expect(received).toEqual([{ control: "close", pressed: true }]);
    dispose();
  });

  it("browser preview returns a safe unsubscribe for native control state", async () => {
    const dispose = await createWindowChromePort({ browserPreview: true }).subscribeControlState(vi.fn());
    expect(dispose).toEqual(expect.any(Function));
    dispose();
  });
});
