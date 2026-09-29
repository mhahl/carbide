/* Carbide console shared behavior: theme manager + log tail.
   Page-specific wiring stays inline in its template. */
(function () {
  "use strict";

  var THEMES = ["wireframe", "light", "dark", "corporate", "nord"];
  var KEY = "carbide-theme";
  var darkQuery = window.matchMedia("(prefers-color-scheme: dark)");

  function storedChoice() {
    try {
      return window.localStorage.getItem(KEY) || "wireframe";
    } catch (err) {
      return "wireframe";
    }
  }

  function resolve(choice) {
    if (choice === "system") {
      return darkQuery.matches ? "dark" : "light";
    }
    return THEMES.indexOf(choice) === -1 ? "wireframe" : choice;
  }

  function syncRadios(choice) {
    var radios = document.querySelectorAll('input[name="theme-choice"]');
    for (var i = 0; i < radios.length; i++) {
      radios[i].checked = radios[i].value === choice;
    }
  }

  function apply(choice) {
    document.documentElement.setAttribute("data-theme", resolve(choice));
    syncRadios(choice);
  }

  function setTheme(choice) {
    try {
      window.localStorage.setItem(KEY, choice);
    } catch (err) {
      /* private mode: theme still applies for this visit */
    }
    apply(choice);
  }

  function onSystemChange() {
    if (storedChoice() === "system") {
      apply("system");
    }
  }

  if (darkQuery.addEventListener) {
    darkQuery.addEventListener("change", onSystemChange);
  } else if (darkQuery.addListener) {
    darkQuery.addListener(onSystemChange);
  }

  document.addEventListener("DOMContentLoaded", function () {
    apply(storedChoice());
  });

  window.CarbideTheme = { set: setTheme, themes: THEMES };

  /* Validated forms: disable the submit button and show a spinner while
     the POST is in flight. Opt in with data-busy on the <form>. */
  document.addEventListener("DOMContentLoaded", function () {
    var forms = document.querySelectorAll("form[data-busy]");
    for (var i = 0; i < forms.length; i++) {
      forms[i].addEventListener("submit", function () {
        var btn = this.querySelector('button[type="submit"]');
        if (!btn || btn.disabled) {
          return;
        }
        btn.disabled = true;
        var label = btn.textContent;
        btn.textContent = "";
        var spinner = document.createElement("span");
        spinner.className = "loading loading-spinner loading-sm";
        spinner.setAttribute("aria-hidden", "true");
        btn.appendChild(spinner);
        btn.appendChild(document.createTextNode(" " + label.trim()));
      });
    }
  });

  /* Live log tail: trim, count, and follow-scroll the SSE-fed lines. */
  window.initLogTail = function () {
    var box = document.getElementById("logbox");
    var lines = document.getElementById("loglines");
    var follow = document.getElementById("log-follow");
    var count = document.getElementById("log-count");
    if (!box || !lines || !follow || !count) {
      return;
    }
    function update() {
      var empty = document.getElementById("log-empty");
      var rows = box.querySelectorAll(".log-line");
      if (empty && rows.length > 0) {
        empty.remove();
      }
      if (rows.length > 2000) {
        for (var i = 0; i < rows.length - 2000; i++) {
          rows[i].remove();
        }
        rows = box.querySelectorAll(".log-line");
      }
      count.textContent = rows.length + " lines";
      if (follow.checked) {
        box.scrollTop = box.scrollHeight;
      }
    }
    lines.addEventListener("htmx:afterSwap", update);
    follow.addEventListener("change", update);
    update();
  };

  document.addEventListener("DOMContentLoaded", function () {
    if (document.getElementById("logbox")) {
      window.initLogTail();
    }
  });
})();
