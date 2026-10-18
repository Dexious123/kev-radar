// Deadline radar interaction: a data block for the dot nearest the pointer, a tap, or the arrow keys,
// and an enlarged view opened by a double-click, the Enlarge button, or Enter.
// The radar SVG is re-rendered by Streamlit on every rerun, so nothing here holds on to it: state is
// per SVG element, and the overlay and the enlarged view hang off document.body, outside the trees
// React manages. Dot text comes from data attributes and is written with textContent only, never as HTML.
// Streamlit passes this file through DOMPurify, which drops a script whose text has a less-than
// sign directly before a letter or a slash, so the source must never contain that pair.
(() => {
  if (window.__kevRadar) return;
  window.__kevRadar = true;

  const SVG_NS = "http://www.w3.org/2000/svg";
  const HOVER_PX = 16;
  const TAP_PX = 26;
  const GAP_PX = 18;
  const states = new WeakMap();

  const overlay = document.createElementNS(SVG_NS, "svg");
  overlay.setAttribute("class", "kr-overlay");
  overlay.setAttribute("aria-hidden", "true");
  const leader = document.createElementNS(SVG_NS, "line");
  leader.setAttribute("class", "kr-leader");
  const reticle = document.createElementNS(SVG_NS, "circle");
  reticle.setAttribute("class", "kr-reticle");
  overlay.append(leader, reticle);

  const block = document.createElement("div");
  block.className = "kr-block";
  block.setAttribute("role", "status");
  block.setAttribute("aria-live", "polite");
  block.hidden = true;
  overlay.style.display = "none";

  const modal = document.createElement("div");
  modal.className = "kr-modal";
  modal.setAttribute("role", "dialog");
  modal.setAttribute("aria-modal", "true");
  modal.setAttribute("aria-label", "Deadline radar, enlarged");
  modal.hidden = true;
  const bar = document.createElement("div");
  bar.className = "kr-bar";
  const heading = document.createElement("p");
  heading.textContent = "Deadline radar";
  const closer = document.createElement("button");
  closer.type = "button";
  closer.className = "kr-close";
  closer.textContent = "Close";
  bar.append(heading, closer);
  const stage = document.createElement("div");
  stage.className = "kr-stage";
  const hint = document.createElement("p");
  hint.className = "kr-hint";
  modal.append(bar, stage, hint);

  document.body.append(modal, overlay, block);

  let current = null; // {svg, dot}
  let pinned = false;
  let opener = null;

  function stateFor(svg) {
    let state = states.get(svg);
    if (!state) {
      const dots = Array.from(svg.querySelectorAll("circle.dot")).map((el) => ({
        el,
        x: Number(el.getAttribute("cx")),
        y: Number(el.getAttribute("cy")),
      }));
      const order = dots.slice().sort((a, b) => Number(a.el.dataset.days) - Number(b.el.dataset.days));
      state = { dots, order };
      states.set(svg, state);
    }
    return state;
  }

  function nearest(svg, clientX, clientY, radiusPx) {
    const matrix = svg.getScreenCTM();
    if (!matrix) return null;
    const point = new DOMPoint(clientX, clientY).matrixTransform(matrix.inverse());
    const reach = radiusPx / matrix.a;
    let best = null;
    let bestDistance = reach * reach;
    for (const dot of stateFor(svg).dots) {
      const dx = dot.x - point.x;
      const dy = dot.y - point.y;
      const distance = dx * dx + dy * dy;
      if (distance <= bestDistance) {
        best = dot;
        bestDistance = distance;
      }
    }
    return best;
  }

  function line(className, text) {
    const element = document.createElement("div");
    element.className = className;
    element.textContent = text;
    return element;
  }

  function fill(dot) {
    const data = dot.el.dataset;
    const band = ["past", "near", "soon", "far"].find((name) => dot.el.classList.contains(name)) || "far";
    const when = document.createElement("div");
    when.className = `when ${band}`;
    when.append(document.createElement("i"), document.createTextNode(data.when || ""));
    const rows = [
      line("cve", data.cve || ""),
      line("host", data.host || ""),
      line("who", [data.owner, data.unit].filter(Boolean).join(", ")),
      when,
      line("due", `Deadline ${data.due || "unknown"}`),
    ];
    if (data.new === "1") rows.push(line("due", "First seen in the latest scan"));
    block.replaceChildren(...rows);
  }

  function place() {
    if (!current) return;
    const { svg, dot } = current;
    if (!svg.isConnected || !dot.el.isConnected) {
      hide();
      return;
    }
    const box = dot.el.getBoundingClientRect();
    const x = box.left + box.width / 2;
    const y = box.top + box.height / 2;
    const width = block.offsetWidth;
    const height = block.offsetHeight;
    const viewWidth = document.documentElement.clientWidth;
    const viewHeight = document.documentElement.clientHeight;
    const above = y - GAP_PX - height >= 8;
    let left;
    if (x + GAP_PX + width <= viewWidth - 8) left = x + GAP_PX;
    else if (x - GAP_PX - width >= 8) left = x - GAP_PX - width;
    else left = x - width / 2; // a phone: neither side fits, so sit directly above or below
    let top = above ? y - GAP_PX - height : y + GAP_PX;
    left = Math.max(8, Math.min(left, viewWidth - width - 8));
    top = Math.max(8, Math.min(top, viewHeight - height - 8));
    block.style.left = `${left}px`;
    block.style.top = `${top}px`;
    // The leader runs from the reticle to the nearest point on the block's edge.
    const endX = Math.max(left, Math.min(x, left + width));
    const endY = Math.max(top, Math.min(y, top + height));
    const ring = Math.max(6, box.width / 2 + 4);
    const angle = Math.atan2(endY - y, endX - x);
    leader.setAttribute("x1", x + Math.cos(angle) * ring);
    leader.setAttribute("y1", y + Math.sin(angle) * ring);
    leader.setAttribute("x2", endX);
    leader.setAttribute("y2", endY);
    reticle.setAttribute("cx", x);
    reticle.setAttribute("cy", y);
    reticle.setAttribute("r", ring);
  }

  function show(svg, dot, pin) {
    const changed = !current || current.dot !== dot;
    current = { svg, dot };
    pinned = pin;
    if (changed) fill(dot);
    block.classList.toggle("pinned", pin);
    block.hidden = false;
    overlay.style.display = "";
    place();
  }

  function hide() {
    current = null;
    pinned = false;
    block.classList.remove("pinned");
    block.hidden = true;
    overlay.style.display = "none";
  }

  // The enlarged view is a copy of the radar. On an upright phone the side labels would take half
  // the width, so the copy crops to the scope and folds each business-unit label inside its slice.
  function geometry(svg) {
    const rings = svg.querySelectorAll("circle.ring");
    const outer = rings[rings.length - 1];
    return {
      cx: Number(outer.getAttribute("cx")),
      cy: Number(outer.getAttribute("cy")),
      r: Number(outer.getAttribute("r")),
    };
  }

  function layout() {
    if (modal.hidden) return;
    const svg = stage.querySelector("svg.radar");
    if (!svg) return;
    const viewWidth = document.documentElement.clientWidth;
    const viewHeight = document.documentElement.clientHeight;
    // A short screen (a phone on its side) gives the scope the full height: Close moves to a corner
    // and the title, key, and hint step aside.
    const compact = viewHeight < 560;
    const fold = compact || viewWidth < 720 || viewWidth < viewHeight;
    modal.classList.toggle("compact", compact);
    const { cx, cy, r } = geometry(svg);
    svg.classList.toggle("folded", fold);
    if (fold) {
      const edge = r + 6;
      svg.setAttribute("viewBox", `${cx - edge} ${cy - edge} ${2 * edge} ${2 * edge}`);
    } else {
      svg.setAttribute("viewBox", svg.dataset.view);
    }
    svg.querySelectorAll("text.slice-label").forEach((label) => {
      if (fold) {
        // Inside the rim; side labels run inward so they never cross the edge.
        const angle = Math.atan2(Number(label.dataset.y) - cy, Number(label.dataset.x) - cx);
        const across = Math.cos(angle);
        label.setAttribute("x", cx + across * (r - 12));
        label.setAttribute("y", cy + Math.sin(angle) * (r - 14));
        label.setAttribute("text-anchor", across > 0.3 ? "end" : across < -0.3 ? "start" : "middle");
      } else {
        label.setAttribute("x", label.dataset.x);
        label.setAttribute("y", label.dataset.y);
        label.setAttribute("text-anchor", label.dataset.anchor);
      }
    });
    const box = svg.getAttribute("viewBox").split(" ").map(Number);
    const key = stage.querySelector(".key");
    const reserved = compact ? 16 : bar.offsetHeight + hint.offsetHeight + (key ? key.offsetHeight : 0) + 64;
    const width = Math.max(200, Math.min(viewWidth - 24, ((viewHeight - reserved) * box[2]) / box[3]));
    svg.style.width = `${width}px`;
  }

  function open(svg) {
    hide();
    const copy = svg.cloneNode(true);
    const renames = { "kr-t": "kr-t-big", "kr-d": "kr-d-big", "kr-sweep": "kr-sweep-big" };
    for (const [from, to] of Object.entries(renames)) {
      const element = copy.querySelector(`[id="${from}"]`);
      if (element) element.id = to;
    }
    copy.setAttribute("aria-labelledby", "kr-t-big");
    copy.setAttribute("aria-describedby", "kr-d-big");
    const sweep = copy.querySelector(".sweep path");
    if (sweep) sweep.setAttribute("fill", "url(#kr-sweep-big)");
    copy.dataset.view = copy.getAttribute("viewBox");
    copy.querySelectorAll("text.slice-label").forEach((label) => {
      label.dataset.x = label.getAttribute("x");
      label.dataset.y = label.getAttribute("y");
      label.dataset.anchor = label.getAttribute("text-anchor") || "middle";
    });
    copy.style.width = "";
    stage.replaceChildren(copy);
    const scope = svg.closest(".scope");
    const key = scope ? scope.querySelector(".key") : null;
    if (key) stage.append(key.cloneNode(true));
    opener = svg;
    hint.textContent = window.matchMedia("(pointer: coarse)").matches
      ? "Tap a dot for details."
      : "Point at a dot for details. Double-click or press Escape to close.";
    modal.hidden = false;
    layout();
    copy.focus({ preventScroll: true });
  }

  function closeModal() {
    if (modal.hidden) return;
    hide();
    modal.hidden = true;
    stage.replaceChildren();
    if (opener && opener.isConnected) opener.focus({ preventScroll: true });
    opener = null;
  }

  document.addEventListener(
    "pointermove",
    (event) => {
      if (pinned || event.pointerType === "touch") return;
      const svg = event.target instanceof Element ? event.target.closest("svg.radar") : null;
      const dot = svg ? nearest(svg, event.clientX, event.clientY, HOVER_PX) : null;
      if (dot) show(svg, dot, false);
      else if (current) hide();
    },
    { passive: true },
  );

  document.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target || block.contains(target)) return;
    const expand = target.closest(".kr-expand");
    if (expand) {
      const scope = expand.closest(".scope");
      const svg = scope ? scope.querySelector("svg.radar") : null;
      if (svg) open(svg);
      return;
    }
    if (target.closest(".kr-close")) {
      closeModal();
      return;
    }
    const svg = target.closest("svg.radar");
    if (!svg) {
      if (current) hide();
      if (modal.contains(target) && !target.closest(".kr-bar, .key")) closeModal();
      return;
    }
    const reach = event.pointerType === "mouse" ? HOVER_PX : TAP_PX;
    const dot = nearest(svg, event.clientX, event.clientY, reach);
    if (!dot || (pinned && current && current.dot === dot)) hide();
    else show(svg, dot, true);
  });

  document.addEventListener("dblclick", (event) => {
    const svg = event.target instanceof Element ? event.target.closest("svg.radar") : null;
    if (!svg) return;
    event.preventDefault();
    if (modal.contains(svg)) closeModal();
    else open(svg);
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      if (current) hide();
      else closeModal();
      return;
    }
    if (!modal.hidden && event.key === "Tab") {
      const stops = [closer, stage.querySelector("svg.radar")].filter(Boolean);
      const at = stops.indexOf(document.activeElement);
      const next = (at + (event.shiftKey ? -1 : 1) + stops.length) % stops.length;
      event.preventDefault();
      stops[next].focus({ preventScroll: true });
      return;
    }
    const svg = document.activeElement;
    if (!(svg instanceof SVGElement) || !svg.matches("svg.radar")) return;
    if (event.key === "Enter" && !modal.contains(svg)) {
      event.preventDefault();
      open(svg);
      return;
    }
    const order = stateFor(svg).order;
    if (!order.length) return;
    const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[event.key];
    let index;
    if (event.key === "Home") index = 0;
    else if (event.key === "End") index = order.length - 1;
    else if (step) {
      const at = current && current.svg === svg ? order.indexOf(current.dot) : -1;
      index = at < 0 ? 0 : (at + step + order.length) % order.length;
    } else return;
    event.preventDefault();
    show(svg, order[index], true);
  });

  document.addEventListener("focusout", (event) => {
    if (current && event.target === current.svg && !pinned) hide();
  });

  const reposition = () => {
    if (current) window.requestAnimationFrame(place);
  };
  document.addEventListener("scroll", reposition, { capture: true, passive: true });
  window.addEventListener(
    "resize",
    () => {
      layout();
      reposition();
    },
    { passive: true },
  );
})();
