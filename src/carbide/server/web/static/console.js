/* Carbide console shared behavior: theme manager + log tail + sortable
   tables. Page-specific wiring stays inline in its template. */
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

  /* Sortable tables: <table data-sortable> gets click-to-sort headers.
     Opt a column out with data-sort="off" on the <th>; force a type with
     data-sort-type="number|text"; override a cell value with
     data-sort-value on the <td>. Clicks cycle ascending, descending,
     then back to the server order. Paginated tables must NOT use this
     (it would sort one page); they sort server-side via header links. */
  function cellValue(td) {
    if (td.hasAttribute("data-sort-value")) {
      return td.getAttribute("data-sort-value");
    }
    return (td.textContent || "").trim();
  }

  function compareText(a, b) {
    return String(a).localeCompare(String(b), undefined,
                                   { numeric: true, sensitivity: "base" });
  }

  function compareValues(a, b, forced) {
    if (forced !== "text") {
      var an = parseFloat(a);
      var bn = parseFloat(b);
      if (a !== "" && b !== "" && !isNaN(an) && !isNaN(bn)) {
        return an - bn;
      }
    }
    if (forced === "number") {
      return 0;
    }
    return compareText(a, b);
  }

  function sortTable(table, th) {
    var headers = th.parentNode.children;
    var index = Array.prototype.indexOf.call(headers, th);
    var type = th.getAttribute("data-sort-type") || "";
    var state = table.getAttribute("data-sort-state") || "";
    var dir = 1;
    if (state === index + ":asc") {
      dir = -1;
    } else if (state === index + ":desc") {
      dir = 0;
    }
    var tbody = table.tBodies[0];
    if (!tbody) {
      return;
    }
    var rows = Array.prototype.slice.call(tbody.rows);
    rows.forEach(function (row, i) {
      if (row.getAttribute("data-sort-pos") === null) {
        row.setAttribute("data-sort-pos", String(i));
      }
    });
    rows.sort(function (ra, rb) {
      if (dir === 0) {
        return (+ra.getAttribute("data-sort-pos") || 0) -
               (+rb.getAttribute("data-sort-pos") || 0);
      }
      var va = ra.cells.length > index ? cellValue(ra.cells[index]) : "";
      var vb = rb.cells.length > index ? cellValue(rb.cells[index]) : "";
      var out = compareValues(va, vb, type);
      if (out === 0) {
        out = (+ra.getAttribute("data-sort-pos") || 0) -
              (+rb.getAttribute("data-sort-pos") || 0);
      }
      return out * dir;
    });
    rows.forEach(function (row) {
      tbody.appendChild(row);
    });
    for (var i = 0; i < headers.length; i++) {
      var h = headers[i];
      if (h.className.indexOf("sortable") === -1) {
        continue;
      }
      var active = dir !== 0 && h === th;
      h.setAttribute("aria-sort", active ?
                     (dir === 1 ? "ascending" : "descending") : "none");
      var ind = h.querySelector(".sort-ind");
      if (ind) {
        ind.textContent = active ? (dir === 1 ? "▲" : "▼") : "";
      }
    }
    table.setAttribute("data-sort-state", dir === 0 ? "" :
                       index + ":" + (dir === 1 ? "asc" : "desc"));
  }

  function enhanceTables(root) {
    var tables = (root || document).querySelectorAll(
      "table[data-sortable]");
    for (var t = 0; t < tables.length; t++) {
      var head = tables[t].tHead;
      if (!head || !head.rows.length) {
        continue;
      }
      var headers = head.rows[0].children;
      for (var i = 0; i < headers.length; i++) {
        (function (th) {
          if (th.getAttribute("data-sort") === "off" ||
              th.className.indexOf("sortable") !== -1) {
            return;
          }
          var btn = document.createElement("button");
          btn.setAttribute("type", "button");
          btn.className = "sort-btn cursor-pointer";
          btn.setAttribute("aria-label", "sort by " +
                           (th.textContent || "").trim());
          while (th.firstChild) {
            btn.appendChild(th.firstChild);
          }
          var ind = document.createElement("span");
          ind.className = "sort-ind";
          ind.setAttribute("aria-hidden", "true");
          btn.appendChild(document.createTextNode(" "));
          btn.appendChild(ind);
          th.appendChild(btn);
          th.className += (th.className ? " " : "") + "sortable";
          th.setAttribute("aria-sort", "none");
        })(headers[i]);
      }
    }
  }

  document.addEventListener("click", function (event) {
    var btn = event.target.closest ?
      event.target.closest("table[data-sortable] th.sortable > button") :
      null;
    if (!btn) {
      return;
    }
    event.preventDefault();
    sortTable(btn.closest("table"), btn.parentNode);
  });

  document.addEventListener("DOMContentLoaded", function () {
    enhanceTables(document);
  });
  document.addEventListener("htmx:afterSwap", function (event) {
    enhanceTables(event.target);
  });
})();
