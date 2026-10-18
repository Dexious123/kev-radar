// Deadline radar interaction: a data block for the dot nearest the pointer, a tap, or the arrow keys.
// The radar SVG is re-rendered by Streamlit on every rerun, so nothing here holds on to it: state is
// per SVG element, and the overlay hangs off document.body, outside the trees React manages.
// Dot text comes from data attributes and is written with textContent only, never as HTML.
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
  document.body.append(overlay, block);

  let current = null; // {svg, dot}
  let pinned = false;

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
    if (target && block.contains(target)) return;
    const svg = target ? target.closest("svg.radar") : null;
    if (!svg) {
      if (current) hide();
      return;
    }
    const reach = event.pointerType === "mouse" ? HOVER_PX : TAP_PX;
    const dot = nearest(svg, event.clientX, event.clientY, reach);
    if (!dot || (pinned && current && current.dot === dot)) hide();
    else show(svg, dot, true);
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      if (current) hide();
      return;
    }
    const svg = document.activeElement;
    if (!(svg instanceof SVGElement) || !svg.matches("svg.radar")) return;
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
  window.addEventListener("resize", reposition, { passive: true });
})();
