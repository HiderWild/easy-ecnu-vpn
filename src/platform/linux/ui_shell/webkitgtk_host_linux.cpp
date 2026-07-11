#include "app/ui_shell/host_bridge.hpp"
#include "app/ui_shell/tray_status_snapshot.hpp"
#include "app/ui_shell/ui_window.hpp"
#include "app/ui_shell/window_layout.hpp"

#if defined(EXV_BUILD_UI_SHELL)
#include <gtk/gtk.h>
#include <webkit2/webkit2.h>
#endif

#include <filesystem>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace exv::platform::linux_ui_shell {

namespace {

#if defined(EXV_BUILD_UI_SHELL)
const char *bridge_script() {
  static constexpr char kBridgeScript[] = R"JS(
(() => {
  if (window.exv || !window.webkit || !window.webkit.messageHandlers || !window.webkit.messageHandlers.exvHost) return;
  let nextId = 1;
  const pending = new Map();
  const subscribers = new Set();
  function rpc(action, payload) {
    const id = nextId++;
    const request = { id, action, payload: payload ?? {} };
    window.webkit.messageHandlers.exvHost.postMessage(JSON.stringify(request));
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
    });
  }
  function unsupported(name) {
    return Promise.reject(new Error(`${name} is not available in the native WebView shell yet.`));
  }
  window.__exvHostReceive = (message) => {
    if (message && typeof message.id === 'number' && pending.has(message.id)) {
      const callbacks = pending.get(message.id);
      pending.delete(message.id);
      if (message.ok) callbacks.resolve(message.data);
      else {
        const error = new Error(message.message || 'Desktop RPC failed');
        error.code = message.code;
        callbacks.reject(error);
      }
      return;
    }
    subscribers.forEach((handler) => handler(message));
  };
  window.exv = {
    status: { get: () => rpc('status.get') },
    vpn: {
      connect: (password) => rpc('vpn.connect', { password }),
      disconnect: () => rpc('vpn.disconnect'),
      connectElevated: (password) => rpc('vpn.connect', { password }),
      disconnectElevated: (backend) => rpc('vpn.disconnect', { backend }),
      authInteraction: () => rpc('vpn.authInteraction.get'),
      respondAuthInteraction: (id, value) => rpc('vpn.authInteraction.respond', { id, value }),
    },
    config: {
      getAuth: () => rpc('config.getAuth'),
      saveAuth: (input) => rpc('config.saveAuth', input),
      getSettings: () => rpc('config.getSettings'),
      saveSettings: (input) => rpc('config.saveSettings', input),
      getKey: () => rpc('config.getKey'),
      importConfig: (input) => rpc('config.import', input ?? {}),
      exportConfig: (input) => rpc('config.export', input ?? {}),
      reset: (confirm) => rpc('config.reset', { confirm }),
    },
    routes: {
      list: () => rpc('routes.list'),
      add: (cidr) => rpc('routes.add', { cidr }),
      remove: (cidr) => rpc('routes.remove', { cidr }),
      reset: () => rpc('routes.reset'),
    },
    service: {
      status: () => rpc('service.status'),
      install: () => rpc('service.install'),
      uninstall: () => rpc('service.uninstall'),
      repair: () => rpc('service.repair'),
    },
    cli: {
      status: () => rpc('cli.status'),
      install: () => rpc('cli.install'),
      uninstall: () => rpc('cli.uninstall'),
    },
    logs: { list: (options) => rpc('logs.list', options ?? {}) },
    runtime: { status: () => rpc('runtime.status') },
    drivers: {
      status: () => rpc('drivers.status'),
      install: (driver) => rpc('drivers.install', { driver }),
    },
    key: {
      status: () => rpc('key.status'),
      reset: (confirm) => rpc('key.reset', { confirm }),
    },
    maintenance: {
      inspectCore: () => rpc('maintenance.inspectCore'),
      killStaleCore: (confirm) => rpc('maintenance.killStaleCore', { confirm }),
    },
    window: {
      setMode: () => Promise.resolve(),
      resizeForMode: () => Promise.resolve({ ok: true, mode: 'advanced' }),
      minimize: () => Promise.resolve({ ok: true }),
      hideToTray: () => Promise.resolve({ ok: true }),
      requestClose: () => Promise.resolve({ ok: true }),
      getClosePreference: () => Promise.resolve({ action: null }),
      setClosePreference: (action) => Promise.resolve({ ok: true, action }),
      resetClosePreference: () => Promise.resolve({ ok: true }),
      resolveClosePrompt: () => Promise.resolve(),
    },
    modal: {
      serviceInstallPrompt: () => Promise.resolve('dismiss'),
      passwordPrompt: (message) => Promise.resolve(window.prompt(message) ?? null),
      confirmPrompt: (message) => Promise.resolve(window.confirm(message)),
      getPayload: () => Promise.resolve(null),
      resolve: () => Promise.resolve(),
    },
    events: {
      subscribe: (handler) => {
        subscribers.add(handler);
        return () => subscribers.delete(handler);
      },
    },
    core: {
      restart: () => rpc('core.restart'),
      quit: () => { window.close(); return Promise.resolve(); },
    },
  };
})();
)JS";
  return kBridgeScript;
}

std::string javascript_string_literal(const std::string &value) {
  std::string out;
  out.reserve(value.size() + 2);
  out.push_back('"');
  for (const char ch : value) {
    switch (ch) {
    case '\\':
      out += "\\\\";
      break;
    case '"':
      out += "\\\"";
      break;
    case '\b':
      out += "\\b";
      break;
    case '\f':
      out += "\\f";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default:
      out.push_back(ch);
      break;
    }
  }
  out.push_back('"');
  return out;
}

std::string renderer_uri(const exv::ui_shell::RendererAssets &renderer) {
  if (renderer.kind == exv::ui_shell::RendererAssetKind::DevServer) {
    return renderer.location;
  }

  const std::filesystem::path absolute =
      std::filesystem::absolute(std::filesystem::path(renderer.location));
  GError *error = nullptr;
  gchar *uri = g_filename_to_uri(absolute.string().c_str(), nullptr, &error);
  if (error != nullptr) {
    g_error_free(error);
  }
  if (uri == nullptr) {
    return {};
  }
  std::string out(uri);
  g_free(uri);
  return out;
}
#endif

} // namespace

[[nodiscard]] exv::ui_shell::WindowBounds
webkitgtk_default_window_bounds() noexcept;

struct WebKitGtkTrayMenuItem {
  std::string label;
  int command_id;
  bool separator;
  bool enabled;
};

constexpr int kTrayCommandShow = 3001;
constexpr int kTrayCommandQuit = 3002;
constexpr int kTrayCommandDisconnect = 3003;

bool webkitgtk_supports_start_hidden_contract() noexcept {
  return true;
}

std::vector<WebKitGtkTrayMenuItem> webkitgtk_tray_menu_model(
    const exv::ui_shell::TrayStatusSnapshot &snapshot) {
  std::vector<WebKitGtkTrayMenuItem> items;
  if (!snapshot.connected) {
    items.push_back({"显示主界面", kTrayCommandShow, false, true});
    items.push_back({"退出", kTrayCommandQuit, false, true});
    return items;
  }
  for (const auto &label : exv::ui_shell::tray_status_snapshot_menu_labels(
           snapshot)) {
    items.push_back({label, 0, false, false});
  }
  items.push_back({"", 0, true, false});
  items.push_back({"断开连接", kTrayCommandDisconnect, false,
                   snapshot.connected});
  items.push_back({"显示主界面", kTrayCommandShow, false, true});
  items.push_back({"", 0, true, false});
  items.push_back({"退出", kTrayCommandQuit, false, true});
  return items;
}

#if defined(EXV_BUILD_UI_SHELL)
class WebKitGtkWindow final : public exv::ui_shell::UiWindow {
public:
  ~WebKitGtkWindow() override { cleanup(); }

  void set_message_handler(exv::ui_shell::HostMessageHandler handler) override {
    handler_ = std::move(handler);
  }

  int run(const exv::ui_shell::UiWindowConfig &config) override {
    active_config_ = config;
    exit_code_ = 0;
    renderer_ready_ = false;

    int argc = 0;
    char **argv = nullptr;
    if (!gtk_init_check(&argc, &argv)) {
      return 70;
    }

    if (!create_window() || !load_renderer(config.renderer)) {
      cleanup();
      return 70;
    }

    running_ = true;
    if (!config.start_hidden) {
      gtk_widget_show_all(window_);
    }
    pump_source_id_ = g_timeout_add(15, &WebKitGtkWindow::on_pump_tick, this);
    gtk_main();

    cleanup();
    return exit_code_;
  }

  void emit_event(const std::string &event_json) override {
    if (webview_ == nullptr || !renderer_ready_) {
      pending_events_.push_back(event_json);
      return;
    }
    post_json_to_renderer(event_json);
  }

  void post_host_response(const std::string &response_json) override {
    post_json_to_renderer(response_json);
  }

  void handle_script_message(const std::string &request_json) {
    if (request_json.empty()) {
      return;
    }

    const std::string response_json =
        handler_ ? handler_(request_json)
                 : R"({"id":0,"ok":false,"code":"host_unavailable","message":"Desktop host bridge is not ready"})";
    if (!response_json.empty()) {
      post_json_to_renderer(response_json);
    }
  }

  void on_load_finished() {
    renderer_ready_ = true;
    flush_pending_events();
  }

private:
  bool create_window() {
    const auto bounds = webkitgtk_default_window_bounds();
    application_ =
        gtk_application_new("cn.ecnu.vpn", G_APPLICATION_FLAGS_NONE);
    if (application_ == nullptr) {
      return false;
    }

    GError *error = nullptr;
    const gboolean registered =
        g_application_register(G_APPLICATION(application_), nullptr, &error);
    if (error != nullptr) {
      g_error_free(error);
    }
    if (!registered) {
      return false;
    }
    g_application_hold(G_APPLICATION(application_));
    application_held_ = true;

    window_ = gtk_application_window_new(application_);
    if (window_ == nullptr) {
      return false;
    }

    gtk_window_set_title(GTK_WINDOW(window_), "EXV");
    gtk_window_set_default_size(GTK_WINDOW(window_), bounds.width,
                                bounds.height);
    gtk_window_set_resizable(GTK_WINDOW(window_), FALSE);
    g_signal_connect(window_, "destroy", G_CALLBACK(&WebKitGtkWindow::on_destroy),
                     this);

    content_manager_ = webkit_user_content_manager_new();
    if (content_manager_ == nullptr) {
      return false;
    }
    webkit_user_content_manager_register_script_message_handler(
        content_manager_, "exvHost");
    g_signal_connect(content_manager_,
                     "script-message-received::exvHost",
                     G_CALLBACK(&WebKitGtkWindow::on_script_message), this);

    WebKitUserScript *script = webkit_user_script_new(
        bridge_script(), WEBKIT_USER_CONTENT_INJECT_ALL_FRAMES,
        WEBKIT_USER_SCRIPT_INJECT_AT_DOCUMENT_START, nullptr, nullptr);
    webkit_user_content_manager_add_script(content_manager_, script);
    webkit_user_script_unref(script);

    GtkWidget *view =
        webkit_web_view_new_with_user_content_manager(content_manager_);
    if (view == nullptr) {
      return false;
    }
    webview_ = WEBKIT_WEB_VIEW(view);
    g_signal_connect(webview_, "load-changed",
                     G_CALLBACK(&WebKitGtkWindow::on_load_changed), this);
    gtk_container_add(GTK_CONTAINER(window_), GTK_WIDGET(webview_));
    return true;
  }

  bool load_renderer(const exv::ui_shell::RendererAssets &renderer) {
    const std::string uri = renderer_uri(renderer);
    if (uri.empty()) {
      return false;
    }
    webkit_web_view_load_uri(webview_, uri.c_str());
    return true;
  }

  void post_json_to_renderer(const std::string &json) {
    if (webview_ == nullptr) {
      pending_events_.push_back(json);
      return;
    }
    const std::string script =
        "window.__exvHostReceive && window.__exvHostReceive(JSON.parse(" +
        javascript_string_literal(json) + "));";
    webkit_web_view_run_javascript(webview_, script.c_str(), nullptr, nullptr,
                                   nullptr);
  }

  void flush_pending_events() {
    std::vector<std::string> events;
    events.swap(pending_events_);
    for (const std::string &event_json : events) {
      post_json_to_renderer(event_json);
    }
  }

  void cleanup() {
    if (pump_source_id_ != 0) {
      g_source_remove(pump_source_id_);
      pump_source_id_ = 0;
    }
    if (content_manager_ != nullptr) {
      webkit_user_content_manager_unregister_script_message_handler(
          content_manager_, "exvHost");
    }
    if (window_ != nullptr) {
      GtkWidget *window = window_;
      window_ = nullptr;
      webview_ = nullptr;
      gtk_widget_destroy(window);
    }
    if (application_held_ && application_ != nullptr) {
      g_application_release(G_APPLICATION(application_));
      application_held_ = false;
    }
    if (application_ != nullptr) {
      g_object_unref(application_);
      application_ = nullptr;
      window_ = nullptr;
    }
    if (content_manager_ != nullptr) {
      g_object_unref(content_manager_);
      content_manager_ = nullptr;
    }
    renderer_ready_ = false;
    running_ = false;
  }

  static gboolean on_pump_tick(gpointer data) {
    auto *owner = static_cast<WebKitGtkWindow *>(data);
    if (owner == nullptr || !owner->running_) {
      return G_SOURCE_REMOVE;
    }
    if (owner->active_config_.pump_core_events) {
      owner->active_config_.pump_core_events();
    }
    if (owner->active_config_.poll_wake_requests) {
      owner->active_config_.poll_wake_requests([owner]() {
        if (owner->window_ != nullptr) {
          gtk_widget_show_all(owner->window_);
          gtk_window_present(GTK_WINDOW(owner->window_));
        }
      });
    }
    return G_SOURCE_CONTINUE;
  }

  static void on_destroy(GtkWidget *, gpointer data) {
    auto *owner = static_cast<WebKitGtkWindow *>(data);
    if (owner != nullptr) {
      owner->running_ = false;
      owner->exit_code_ = 0;
      owner->window_ = nullptr;
      owner->webview_ = nullptr;
    }
    gtk_main_quit();
  }

  static void on_load_changed(WebKitWebView *, WebKitLoadEvent event,
                              gpointer data) {
    if (event != WEBKIT_LOAD_FINISHED) {
      return;
    }
    auto *owner = static_cast<WebKitGtkWindow *>(data);
    if (owner != nullptr) {
      owner->on_load_finished();
    }
  }

  static void on_script_message(WebKitUserContentManager *,
                                WebKitJavascriptResult *result,
                                gpointer data) {
    auto *owner = static_cast<WebKitGtkWindow *>(data);
    if (owner == nullptr || result == nullptr) {
      return;
    }

    JSCValue *value = webkit_javascript_result_get_js_value(result);
    if (value == nullptr) {
      return;
    }
    gchar *message = jsc_value_to_string(value);
    if (message == nullptr) {
      return;
    }
    owner->handle_script_message(std::string(message));
    g_free(message);
  }

  exv::ui_shell::HostMessageHandler handler_;
  exv::ui_shell::UiWindowConfig active_config_;
  GtkApplication *application_ = nullptr;
  GtkWidget *window_ = nullptr;
  WebKitWebView *webview_ = nullptr;
  WebKitUserContentManager *content_manager_ = nullptr;
  std::vector<std::string> pending_events_;
  guint pump_source_id_ = 0;
  bool application_held_ = false;
  bool running_ = false;
  bool renderer_ready_ = false;
  int exit_code_ = 70;
};
#else
class WebKitGtkWindow final : public exv::ui_shell::UiWindow {
public:
  void set_message_handler(exv::ui_shell::HostMessageHandler handler) override {
    handler_ = std::move(handler);
  }

  int run(const exv::ui_shell::UiWindowConfig &) override { return 70; }

  void emit_event(const std::string &event_json) override {
    last_event_json_ = event_json;
  }

private:
  exv::ui_shell::HostMessageHandler handler_;
  std::string last_event_json_;
};
#endif

exv::ui_shell::WindowBounds webkitgtk_default_window_bounds() noexcept {
  return exv::ui_shell::kElectronAdvancedWindowBounds;
}

std::string dispatch_webkitgtk_host_message(
    const std::string &message_json,
    const exv::ui_shell::CoreRpcInvoker &invoke_core) {
  return exv::ui_shell::handle_host_request(message_json, invoke_core);
}

std::unique_ptr<exv::ui_shell::UiWindow> create_webkitgtk_window() {
  return std::make_unique<WebKitGtkWindow>();
}

} // namespace exv::platform::linux_ui_shell
