// Site page: super-spines by plane, border routers and backbone routers for each site, and the links between them.
// 3D (drag to rotate), every device on screen at open, broken / partly broken links and drained devices each look
// different (legend at the bottom), and a sortable, filterable table to find answers fast.
// Everything is drawn from the loaded topology; nothing about counts or sizes is hard-coded.
// All code, helpers too, lives inside kit.page(...) so it cannot clash with other pages.

kit.page('site', function () {
  let current = null;

  // ===== Shared 3D map engine. The same copy sits inside each page file, so every page stays self-contained. =====
  const TIER_NAME = { top_of_rack: 'Racks', spine: 'Spines', super_spine: 'Super-spines', border: 'Border routers', backbone_router: 'Backbone routers' };
  const byNum = (a, b) => (a ?? -1) - (b ?? -1);
  const uniq = (arr) => [...new Set(arr)];

  // Lay out blocks {w, d, h} in a grid whose shape best fills a screen of the given aspect; sets b.ox, b.oz.
  function arrangeBlocks(blocks, aspect, gapX, gapZ) {
    if (!blocks.length) return;
    const maxW = d3.max(blocks, (b) => b.w), maxD = d3.max(blocks, (b) => b.d), maxH = d3.max(blocks, (b) => b.h || 0);
    let best = 1, bestScore = Infinity;
    for (let c = 1; c <= blocks.length; c++) {
      const r = Math.ceil(blocks.length / c);
      const W = c * maxW + (c - 1) * gapX, D = (r * maxD + (r - 1) * gapZ) * 0.72 + maxH * 0.75;
      const score = Math.max(W / aspect, D);
      if (score < bestScore - 1e-9) { bestScore = score; best = c; }
    }
    blocks.forEach((b, i) => { b.ox = (i % best) * (maxW + gapX) + (maxW - b.w) / 2; b.oz = Math.floor(i / best) * (maxD + gapZ); });
  }
  // A row of n items centred on cx with the given pitch, squeezed to fit maxW.
  function rowX(i, n, cx, pitch, maxW) {
    const p = n > 1 ? Math.min(pitch, maxW / (n - 1)) : 0;
    return cx + (i - (n - 1) / 2) * p;
  }
  function deviceGroup(kit, d, links) {
    return { key: d.id, label: d.id, find: kit.siteName(d.site) + ' ' + d.tier, sk: [d.site, d.pod ?? -1, d.plane ?? -1, d.id], nodes: new Set([d.id]), links };
  }

  function engine(el, model, kit, cfg) {
    const RANK = window.MapCore.TIER_RANK;
    const C = {
      bg: 0xf4f6fa, plate: 0xe8ecf1, plateEdge: 0xc9d1db, empty: 0x6e7781,
      partial: 0xf0a020, broken: 0xd1242f, drained: 0x8250df, select: 0x1f6feb, dim: 0xe9ecf1, lineOk: 0x9aa6b4,
    };
    const TIERC = { top_of_rack: 0x7cc6a0, spine: 0x5fb3a3, super_spine: 0x4a9a9c, border: 0x3d7d8f, backbone_router: 0x33607a };
    const css = (n) => '#' + n.toString(16).padStart(6, '0');
    const other = (l, id) => (l.a === id ? l.b : l.a);
    const isBad = (l) => l.up < l.count;
    const V = (a) => (a instanceof THREE.Vector3 ? a.clone() : new THREE.Vector3(a[0], a[1], a[2]));
    const R = cfg.tube || 0.06;

    const nodes = cfg.nodes.filter((n) => n.p && kit.device(n.id));
    const byId = new Map(nodes.map((n) => [n.id, n]));
    for (const n of nodes) {
      n.d = kit.device(n.id);
      n.p = V(n.p);
      n.s = V(n.s || [0.8, 0.6, 0.8]);
    }
    const links = uniq(cfg.links).filter((l) => byId.has(l.a) && byId.has(l.b));
    // a device's colour reflects the links this page draws
    for (const n of nodes) { n.broken = 0; n.partial = 0; }
    for (const l of links) {
      const k = l.up === 0 ? 'broken' : l.up < l.count ? 'partial' : null;
      if (k) { byId.get(l.a)[k]++; byId.get(l.b)[k]++; }
    }
    for (const n of nodes) n.bad = n.broken + n.partial;
    const pathOf = new Map();
    for (const l of links) {
      const a = byId.get(l.a).p, b = byId.get(l.b).p;
      const h = cfg.arc ? cfg.arc(l, a, b) : 0;
      if (h) {
        const mid = a.clone().add(b).multiplyScalar(0.5);
        mid.y = Math.max(a.y, b.y) + h;
        pathOf.set(l, new THREE.QuadraticBezierCurve3(a, mid, b).getPoints(28));
      } else pathOf.set(l, [a, b]);
    }

    // ---------- DOM ----------
    el.innerHTML = '';
    const root = document.createElement('div');
    root.className = 'mx-root';
    root.innerHTML = `
      <style>
        .mx-root{position:absolute;inset:0;display:flex;font-size:12px}
        .mx-view{position:relative;flex:1;min-width:0;background:${css(C.bg)}}
        .mx-view canvas{display:block}
        .mx-side{width:clamp(280px,36%,440px);flex:none;display:flex;flex-direction:column;border-left:1px solid var(--border);background:#fff;min-height:0}
        .mx-side.min{width:36px}.mx-side.min>*:not(.mx-collapse){display:none}
        .mx-head{padding:10px 12px 6px;display:flex;flex-wrap:wrap;gap:6px;align-items:center}
        .mx-head b{font-size:13px;margin-right:auto}
        .mx-seg{display:inline-flex;flex-wrap:wrap;background:#eef1f5;border-radius:8px;padding:2px}
        .mx-seg button{border:0;background:none;padding:3px 8px;border-radius:6px;cursor:pointer;color:var(--muted);font-size:12px}
        .mx-seg button.on{background:#fff;color:var(--accent);font-weight:600;box-shadow:0 1px 2px rgba(0,0,0,.12)}
        .mx-filter{width:100%;padding:5px 8px;border:1px solid var(--border);border-radius:7px;font:inherit}
        .mx-tablewrap{flex:1;overflow:auto;min-height:0;border-top:1px solid var(--border)}
        .mx-table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums;font-size:11.5px}
        .mx-table th{position:sticky;top:0;background:#f6f8fa;color:var(--muted);font-weight:600;padding:5px 4px;text-align:right;cursor:pointer;user-select:none;border-bottom:1px solid var(--border);white-space:nowrap;font-size:11px}
        .mx-table th:first-child,.mx-table td:first-child{text-align:left;padding-left:10px;white-space:nowrap}
        .mx-table th.sorted{color:var(--accent)}
        .mx-table td{padding:3px 5px;text-align:right;border-bottom:1px solid #f0f2f5;cursor:pointer}
        .mx-table tr:hover td{background:#f3f7ff}
        .mx-table tr.on td{background:var(--accent-soft)}
        .mx-table tr.total td{font-weight:700;background:#fafbfc;cursor:default}
        .mx-table td.z{color:#c3c9d1}
        .mx-table td.hb{color:${css(C.broken)};font-weight:700}
        .mx-table td.hp{color:#b26b00;font-weight:700}
        .mx-table td.hd{color:${css(C.drained)};font-weight:700}
        .mx-legend{position:absolute;left:10px;right:10px;bottom:8px;display:flex;flex-wrap:wrap;align-items:center;gap:2px 4px;background:rgba(255,255,255,.94);border:1px solid var(--border);border-radius:10px;padding:5px 8px;box-shadow:0 2px 8px rgba(0,0,0,.06)}
        .mx-legend .t{font-weight:700;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.06em;margin:0 2px 0 6px}
        .mx-legend .i{display:flex;align-items:center;gap:6px;padding:2px 6px;border-radius:6px}
        .mx-legend .i[data-k]{cursor:pointer}
        .mx-legend .i[data-k]:hover{background:#eef1f5}.mx-legend .i.on{background:var(--accent-soft);font-weight:600}
        .mx-legend .n{color:var(--muted);font-variant-numeric:tabular-nums}
        .mx-legend .br{flex-basis:100%;height:0}
        .mx-sw{width:13px;height:11px;border-radius:2px;flex:none;display:inline-block}
        .mx-ln{width:22px;height:0;flex:none;border-top:3px solid}
        .mx-tools{position:absolute;right:10px;top:10px;display:flex;gap:6px}
        .mx-tools button,.mx-collapse{border:1px solid var(--border);background:#fff;border-radius:7px;padding:4px 9px;cursor:pointer;font-size:12px;color:var(--text)}
        .mx-tools button.on{background:var(--accent-soft);color:var(--accent);border-color:#b6cdf8}
        .mx-collapse{margin:8px 6px 0 auto;padding:3px 7px}
        .mx-tip{position:absolute;pointer-events:none;background:rgba(24,28,34,.94);color:#fff;border-radius:8px;padding:7px 9px;font-size:12px;line-height:1.45;display:none;white-space:nowrap;z-index:5}
        .mx-tip .id{font-family:ui-monospace,Menlo,monospace;font-weight:700}
        .mx-tip .b{color:#ff8a8f}.mx-tip .p{color:#ffc65c}.mx-tip .d{color:#c8a6ff}
        .mx-focus{position:absolute;left:50%;top:10px;transform:translateX(-50%);background:var(--accent);color:#fff;border-radius:999px;padding:4px 6px 4px 12px;display:none;align-items:center;gap:8px;font-weight:600;box-shadow:0 2px 6px rgba(47,111,235,.3);white-space:nowrap}
        .mx-focus button{border:0;background:rgba(255,255,255,.25);color:#fff;border-radius:999px;padding:1px 8px;cursor:pointer}
        .mx-hint{position:absolute;left:12px;top:12px;color:#8c959f;font-size:11px;max-width:calc(100% - 330px);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
      </style>
      <div class="mx-view">
        <div class="mx-tools">
          <button data-t="okLinks" class="on" title="Show healthy links too">Healthy links</button>
          <button data-t="top" title="Look straight down">Top view</button>
          <button data-t="reset">Reset view</button>
        </div>
        <div class="mx-focus"><span></span><button title="Clear (Esc)">✕</button></div>
        <div class="mx-legend"></div>
        <div class="mx-hint">Drag to rotate · scroll to zoom · right-drag to pan · click a device to select</div>
        <div class="mx-tip"></div>
      </div>
      <div class="mx-side">
        <button class="mx-collapse" title="Hide or show the table">⇥</button>
        <div class="mx-head">
          <b>Group by</b>
          <span class="mx-seg">${cfg.groupings.map((g, i) => `<button data-g="${i}" class="${i ? '' : 'on'}">${g.name}</button>`).join('')}</span>
          <input class="mx-filter" type="search" placeholder="Filter rows (device, site name, pod 3, plane 2...)">
        </div>
        <div class="mx-tablewrap"><table class="mx-table"></table></div>
        <div class="note" style="padding:6px 10px">Click a column to sort · click a row to highlight it · Bad = broken + partly broken</div>
      </div>`;
    el.appendChild(root);
    const view = root.querySelector('.mx-view');
    const tip = root.querySelector('.mx-tip');
    const legendEl = root.querySelector('.mx-legend');
    const focusEl = root.querySelector('.mx-focus');
    const side = root.querySelector('.mx-side');
    const tableEl = root.querySelector('.mx-table');
    const filterEl = root.querySelector('.mx-filter');

    // ---------- scene ----------
    const renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setClearColor(C.bg);
    view.prepend(renderer.domElement);
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 1e6);
    const controls = new THREE.OrbitControls(camera, renderer.domElement);
    controls.maxPolarAngle = Math.PI / 2 - 0.02;
    scene.add(new THREE.HemisphereLight(0xffffff, 0xb8c0cc, 1.6));
    const sun = new THREE.DirectionalLight(0xffffff, 1.4);
    sun.position.set(-30, 60, 40);
    scene.add(sun);
    const disposables = [];
    const track = (o) => { disposables.push(o); return o; };
    const bbox = new THREE.Box3();

    function textCanvas(text, color, weight) {
      const c = document.createElement('canvas');
      const ctx = c.getContext('2d');
      const fs = 64, font = `${weight} ${fs}px -apple-system, Segoe UI, Roboto, sans-serif`;
      ctx.font = font;
      c.width = Math.ceil(ctx.measureText(text).width) + 16; c.height = fs + 16;
      ctx.font = font; ctx.fillStyle = color; ctx.textBaseline = 'middle'; ctx.textAlign = 'center';
      ctx.fillText(text, c.width / 2, c.height / 2);
      return c;
    }
    function addLabel({ text, p, h = 1, color = '#1f2328', weight = 700, flat = false }) {
      const c = textCanvas(String(text), color, weight);
      const tex = track(new THREE.CanvasTexture(c));
      tex.anisotropy = 4;
      const w = (h * c.width) / c.height;
      const pos = V(p);
      if (flat) {
        const m = new THREE.Mesh(track(new THREE.PlaneGeometry(w, h)), track(new THREE.MeshBasicMaterial({ map: tex, transparent: true, depthWrite: false })));
        m.rotation.x = -Math.PI / 2;
        m.position.copy(pos);
        scene.add(m);
      } else {
        const s = new THREE.Sprite(track(new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false })));
        s.scale.set(w, h, 1);
        s.position.copy(pos);
        scene.add(s);
      }
      bbox.expandByPoint(pos);
    }
    for (const pl of cfg.plates || []) {
      const g = track(new THREE.BoxGeometry(pl.w, pl.t || 0.2, pl.d));
      const m = new THREE.Mesh(g, track(new THREE.MeshLambertMaterial({ color: pl.color || C.plate, transparent: !!pl.opacity, opacity: pl.opacity || 1 })));
      m.position.set(pl.x, (pl.y || 0) - (pl.t || 0.2) / 2, pl.z);
      scene.add(m);
      const e = new THREE.LineSegments(track(new THREE.EdgesGeometry(g)), track(new THREE.LineBasicMaterial({ color: C.plateEdge })));
      e.position.copy(m.position);
      scene.add(e);
      bbox.expandByPoint(new THREE.Vector3(pl.x - pl.w / 2, pl.y || 0, pl.z - pl.d / 2));
      bbox.expandByPoint(new THREE.Vector3(pl.x + pl.w / 2, pl.y || 0, pl.z + pl.d / 2));
    }
    for (const lb of cfg.labels || []) addLabel(lb);
    if (cfg.empties && cfg.empties.length) {
      const pts = [];
      for (const e of cfg.empties) {
        const [x, y, z] = e.p, hw = e.w / 2, hd = e.d / 2, yy = y + 0.01;
        pts.push(x - hw, yy, z - hd, x + hw, yy, z - hd, x + hw, yy, z - hd, x + hw, yy, z + hd, x + hw, yy, z + hd, x - hw, yy, z + hd, x - hw, yy, z + hd, x - hw, yy, z - hd, x - hw, yy, z - hd, x + hw, yy, z + hd);
      }
      const g = track(new THREE.BufferGeometry());
      g.setAttribute('position', new THREE.Float32BufferAttribute(pts, 3));
      const ls = new THREE.LineSegments(g, track(new THREE.LineDashedMaterial({ color: C.empty, dashSize: 0.1, gapSize: 0.07 })));
      ls.computeLineDistances();
      scene.add(ls);
    }

    const mesh = new THREE.InstancedMesh(track(new THREE.BoxGeometry(1, 1, 1)), track(new THREE.MeshLambertMaterial()), Math.max(nodes.length, 1));
    mesh.count = nodes.length;
    const mtx = new THREE.Matrix4(), quat = new THREE.Quaternion();
    nodes.forEach((n, i) => {
      mtx.compose(n.p, quat, n.s);
      mesh.setMatrixAt(i, mtx);
      bbox.expandByPoint(n.p.clone().add(n.s.clone().multiplyScalar(0.5)));
      bbox.expandByPoint(n.p.clone().sub(n.s.clone().multiplyScalar(0.5)));
    });
    scene.add(mesh);
    for (const pts of pathOf.values()) for (const p of pts) bbox.expandByPoint(p);
    if (bbox.isEmpty()) bbox.set(new THREE.Vector3(-1, 0, -1), new THREE.Vector3(1, 1, 1));

    // striped texture for partly broken links
    const stripe = document.createElement('canvas');
    stripe.width = 64; stripe.height = 4;
    { const x = stripe.getContext('2d'); x.fillStyle = css(C.partial); x.fillRect(0, 0, 40, 4); }
    const stripeTex = track(new THREE.CanvasTexture(stripe));
    stripeTex.wrapS = THREE.RepeatWrapping;

    const linkGroup = new THREE.Group();
    scene.add(linkGroup);
    const tubeMeshes = [];

    // ---------- state ----------
    let showOk = true, focus = null, legendFilter = null, selected = kit.selected;
    let gIdx = 0, sortCol = 'name', sortDir = 1;

    const nodeLegend = (n) => {
      const f = legendFilter;
      if (!f) return true;
      if (f === 'ok') return !n.bad && !n.d.drained;
      if (f === 'partial') return n.partial > 0;
      if (f === 'broken') return n.broken > 0;
      if (f === 'drained') return n.d.drained;
      if (f === 'lbroken') return links.some((l) => l.up === 0 && (l.a === n.id || l.b === n.id));
      if (f === 'lpartial') return links.some((l) => l.up > 0 && l.up < l.count && (l.a === n.id || l.b === n.id));
      return true;
    };
    const linkLegend = (l) => {
      const f = legendFilter;
      if (!f) return true;
      if (f === 'broken' || f === 'lbroken') return l.up === 0;
      if (f === 'partial' || f === 'lpartial') return l.up > 0 && l.up < l.count;
      if (f === 'drained') return byId.get(l.a).d.drained || byId.get(l.b).d.drained;
      if (f === 'ok') return l.up === l.count;
      return true;
    };
    const anyFilter = () => !!(focus || legendFilter);
    const nodeLit = (n) => (!focus || focus.nodes.has(n.id)) && nodeLegend(n);
    const linkLit = (l) => (!focus || focus.links.has(l)) && linkLegend(l);

    const col = new THREE.Color(), dimC = new THREE.Color(C.dim);
    function paint() {
      nodes.forEach((n, i) => {
        const base = n.d.drained ? C.drained : n.broken ? C.broken : n.partial ? C.partial : TIERC[n.d.tier] || 0x5f7f99;
        col.set(n.id === selected ? C.select : base);
        if (!nodeLit(n) && n.id !== selected) col.lerp(dimC, 0.85);
        mesh.setColorAt(i, col);
      });
      if (mesh.instanceColor) mesh.instanceColor.needsUpdate = true;
      buildLinks();
      render();
    }
    function buildLinks() {
      for (const c of [...linkGroup.children]) {
        c.geometry.dispose();
        if (c.material.map && c.material.map !== stripeTex) c.material.map.dispose();
        c.material.dispose();
        linkGroup.remove(c);
      }
      tubeMeshes.length = 0;
      const ok = [], sel = [];
      const pushSeg = (arr, pts) => { for (let i = 0; i < pts.length - 1; i++) arr.push(pts[i].x, pts[i].y, pts[i].z, pts[i + 1].x, pts[i + 1].y, pts[i + 1].z); };
      for (const l of links) {
        const pts = pathOf.get(l);
        const isSel = selected && (l.a === selected || l.b === selected);
        if (isSel) pushSeg(sel, pts);
        const lit = linkLit(l);
        if (!lit && anyFilter()) continue;
        if (l.up === l.count) {
          if (!isSel && showOk) {
            if (cfg.okTubes) tube(l, pts, 0xaab4c0, R * 0.6);
            else pushSeg(ok, pts);
          }
          continue;
        }
        tube(l, pts, l.up === 0 ? C.broken : null, R);
      }
      const add = (pts, mat) => {
        if (!pts.length) return;
        const g = new THREE.BufferGeometry();
        g.setAttribute('position', new THREE.Float32BufferAttribute(pts, 3));
        linkGroup.add(new THREE.LineSegments(g, mat));
      };
      add(ok, new THREE.LineBasicMaterial({ color: C.lineOk, transparent: true, opacity: anyFilter() ? 0.55 : (cfg.okOpacity || 0.25), depthWrite: false }));
      add(sel, new THREE.LineBasicMaterial({ color: C.select }));
    }
    function tube(l, pts, color, r) {
      const curve = pts.length > 2 ? new THREE.CatmullRomCurve3(pts) : new THREE.LineCurve3(pts[0], pts[1]);
      const g = new THREE.TubeGeometry(curve, pts.length > 2 ? 40 : 1, r, 6, false);
      let m;
      if (color == null) {
        const t = stripeTex.clone();
        t.needsUpdate = true;
        t.repeat.set(Math.max(1, curve.getLength() / (r * 12)), 1);
        m = new THREE.MeshBasicMaterial({ map: t, transparent: true, alphaTest: 0.3 });
      } else m = new THREE.MeshBasicMaterial({ color });
      const tm = new THREE.Mesh(g, m);
      tm.userData.link = l;
      linkGroup.add(tm);
      tubeMeshes.push(tm);
    }

    // ---------- camera ----------
    let W = 0, H = 0;
    const legendH = () => Math.min(legendEl.offsetHeight + 16, H * 0.3);
    function fit(top) {
      const center = bbox.getCenter(new THREE.Vector3());
      const el0 = cfg.elev ?? 0.85, az = cfg.azim ?? 0;
      const dir = top ? new THREE.Vector3(0, 1, 0.0001).normalize()
        : new THREE.Vector3(Math.sin(az) * Math.cos(el0), Math.sin(el0), Math.cos(az) * Math.cos(el0));
      const lh = legendH();
      camera.aspect = W / (H + lh);
      camera.setViewOffset(W, H + lh, 0, 0, W, H);
      const minY = -1 + (2 * lh) / H + 0.02;
      const corners = [];
      for (const x of [bbox.min.x, bbox.max.x]) for (const y of [bbox.min.y, bbox.max.y]) for (const z of [bbox.min.z, bbox.max.z]) corners.push(new THREE.Vector3(x, y, z));
      let lo = 0.5, hi = 20000;
      for (let k = 0; k < 44; k++) {
        const d = (lo + hi) / 2;
        camera.position.copy(center).addScaledVector(dir, d);
        camera.lookAt(center);
        camera.updateMatrixWorld();
        const okk = corners.every((c) => { const v = c.clone().project(camera); return Math.abs(v.x) < 0.95 && v.y > minY && v.y < 0.86 && v.z < 1; });
        if (okk) hi = d; else lo = d;
      }
      camera.position.copy(center).addScaledVector(dir, hi);
      controls.target.copy(center);
      controls.update();
      render();
    }
    function size() {
      const w = view.clientWidth, h = view.clientHeight;
      if (!w || !h) return;
      if (w === W && h === H) return;
      W = w; H = h;
      renderer.setSize(w, h);
      fit(false);
    }
    let raf = 0;
    function render() {
      if (raf) return;
      raf = requestAnimationFrame(() => { raf = 0; renderer.render(scene, camera); });
    }
    controls.addEventListener('change', render);
    const ro = new ResizeObserver(size);
    ro.observe(view);

    // ---------- legend ----------
    const cnt = {
      ok: nodes.filter((n) => !n.bad && !n.d.drained).length,
      partial: nodes.filter((n) => n.partial).length,
      broken: nodes.filter((n) => n.broken).length,
      drained: nodes.filter((n) => n.d.drained).length,
      lok: links.filter((l) => l.up === l.count).length,
      lpartial: links.filter((l) => l.up > 0 && l.up < l.count).length,
      lbroken: links.filter((l) => l.up === 0).length,
    };
    function drawLegend() {
      const it = (k, sw, label, n) => `<div class="i ${legendFilter === k ? 'on' : ''}" data-k="${k}">${sw}<span>${label}</span><span class="n">${n}</span></div>`;
      const box = (c) => `<span class="mx-sw" style="background:${css(c)}"></span>`;
      const tiers = uniq(nodes.map((n) => n.d.tier)).sort((a, b) => RANK[a] - RANK[b]);
      legendEl.innerHTML =
        `<div class="t">${cfg.deviceWord || 'Devices'} · click to filter</div>` +
        it('ok', tiers.map((t) => box(TIERC[t])).join(''), 'All links up', cnt.ok) +
        it('partial', box(C.partial), 'Has a partly broken link (shown here)', cnt.partial) +
        it('broken', box(C.broken), 'Has a broken link (shown here)', cnt.broken) +
        it('drained', box(C.drained), 'Drained', cnt.drained) +
        (cfg.empties ? `<div class="i"><span class="mx-sw" style="border:1.5px dashed ${css(C.empty)}"></span>Missing rack (empty slot) <span class="n">${cfg.empties.length}</span></div>` : '') +
        `<div class="br"></div><div class="t">${cfg.linkWord || 'Links'}</div>` +
        `<div class="i"><span class="mx-ln" style="border-color:${css(C.lineOk)}"></span>Up <span class="n">${cnt.lok}</span></div>` +
        it('lpartial', `<span class="mx-ln" style="border-top-style:dashed;border-color:${css(C.partial)}"></span>`, 'Partly broken (some parallel links down)', cnt.lpartial) +
        it('lbroken', `<span class="mx-ln" style="border-color:${css(C.broken)}"></span>`, 'Broken (all down)', cnt.lbroken) +
        `<div class="i">${box(C.select)}Selected</div>`;
    }
    legendEl.addEventListener('click', (e) => {
      const i = e.target.closest('.i[data-k]');
      if (!i) return;
      legendFilter = legendFilter === i.dataset.k ? null : i.dataset.k;
      drawLegend(); paint();
    });

    // ---------- table ----------
    const TITLE = {
      devices: 'Devices in the row', links: 'Links counted for the row', bad: 'Links not fully up (broken + partly broken)',
      badUp: 'Bad links going UP to a higher tier', badDown: 'Bad links going DOWN to a lower tier',
      broken: 'Links fully down', partial: 'Links partly down (some parallel links down)', drained: 'Drained devices',
      down: 'Individual links down, counting parallel links',
    };
    const HEAD = { devices: 'Devices', links: 'Links', bad: 'Bad', badUp: 'Bad ↑', badDown: 'Bad ↓', broken: 'Broken', partial: 'Partly', drained: 'Drained', down: 'Down' };
    const DEF_COLS = {
      device: ['bad', 'badUp', 'badDown', 'broken', 'partial', 'drained'],
      group: ['devices', 'links', 'bad', 'broken', 'partial', 'drained', 'down'],
    };
    function stats(nodeSet, ls) {
      const s = { devices: nodeSet.size, links: ls.length, bad: 0, badUp: 0, badDown: 0, broken: 0, partial: 0, drained: 0, down: 0 };
      for (const id of nodeSet) if (kit.device(id)?.drained) s.drained++;
      for (const l of ls) {
        s.down += l.count - l.up;
        if (l.up === l.count) continue;
        s.bad++;
        if (l.up === 0) s.broken++; else s.partial++;
        for (const e of [l.a, l.b]) {
          if (!nodeSet.has(e)) continue;
          const r1 = RANK[kit.device(e).tier], r2 = RANK[kit.device(other(l, e)).tier];
          if (r2 > r1) s.badUp++; else if (r2 < r1) s.badDown++;
        }
      }
      return s;
    }
    const grp = () => cfg.groupings[gIdx];
    const colsOf = () => ['name', ...(grp().cols || DEF_COLS[grp().kind || 'group'])];
    const cache = new Map();
    function rows() {
      if (!cache.has(gIdx)) {
        cache.set(gIdx, grp().groups().map((g) => Object.assign(g, stats(g.nodes, g.links), { links: g.links, nLinks: g.links.length })));
      }
      return cache.get(gIdx);
    }
    const val = (g, k) => (k === 'links' ? g.nLinks : g[k]);
    function cmpName(a, b) {
      for (let i = 0; i < Math.max(a.sk.length, b.sk.length); i++) {
        const c = typeof a.sk[i] === 'number' && typeof b.sk[i] === 'number' ? a.sk[i] - b.sk[i] : d3.ascending(String(a.sk[i]), String(b.sk[i]));
        if (c) return c;
      }
      return 0;
    }
    function drawTable() {
      let gs = rows().slice();
      const q = filterEl.value.trim().toLowerCase();
      if (q) gs = gs.filter((g) => (g.label + ' ' + g.key + ' ' + (g.find || '')).toLowerCase().includes(q));
      gs.sort((a, b) => (sortCol === 'name' ? cmpName(a, b) * sortDir : (val(b, sortCol) - val(a, sortCol)) * sortDir || cmpName(a, b)));
      const cols = colsOf();
      const allN = new Set(), allL = new Set();
      for (const g of gs) { g.nodes.forEach((x) => allN.add(x)); g.links.forEach((x) => allL.add(x)); }
      const tot = stats(allN, [...allL]);
      const cell = (k, v) => {
        const c = !v ? 'z' : k === 'bad' || k === 'broken' || k === 'down' || k === 'badUp' || k === 'badDown' ? 'hb' : k === 'partial' ? 'hp' : k === 'drained' ? 'hd' : '';
        return `<td class="${c}">${v}</td>`;
      };
      const arrow = (k) => (sortCol !== k ? '' : k === 'name' ? (sortDir > 0 ? ' ▲' : ' ▼') : sortDir > 0 ? ' ▼' : ' ▲');
      tableEl.innerHTML =
        `<tr>${cols.map((k) => `<th data-c="${k}" class="${sortCol === k ? 'sorted' : ''}" title="${k === 'name' ? 'Sort by name' : TITLE[k]}">${k === 'name' ? grp().title || grp().name : HEAD[k]}${arrow(k)}</th>`).join('')}</tr>` +
        gs.map((g) => `<tr data-k="${g.key}" class="${focus && focus.key === g.key ? 'on' : ''}">${cols.map((k) => (k === 'name' ? `<td title="${g.label}">${g.label}</td>` : cell(k, val(g, k)))).join('')}</tr>`).join('') +
        `<tr class="total">${cols.map((k) => (k === 'name' ? `<td>Total (${gs.length} rows)</td>` : `<td>${k === 'links' ? allL.size : tot[k]}</td>`)).join('')}</tr>`;
      tableEl._g = new Map(gs.map((g) => [g.key, g]));
    }
    tableEl.addEventListener('click', (e) => {
      const th = e.target.closest('th');
      if (th) {
        const c = th.dataset.c;
        if (sortCol === c) sortDir = -sortDir; else { sortCol = c; sortDir = 1; }
        drawTable();
        return;
      }
      const tr = e.target.closest('tr[data-k]');
      if (!tr) return;
      const g = tableEl._g.get(tr.dataset.k);
      setFocus(focus && focus.key === g.key ? null : { key: g.key, label: g.label, nodes: g.nodes, links: new Set(g.links.length ? g.links : links.filter((l) => g.nodes.has(l.a) || g.nodes.has(l.b))) });
    });
    root.querySelectorAll('.mx-seg button').forEach((b) => b.addEventListener('click', () => {
      root.querySelectorAll('.mx-seg button').forEach((x) => x.classList.toggle('on', x === b));
      gIdx = +b.dataset.g;
      filterEl.value = '';
      if (!colsOf().includes(sortCol)) { sortCol = 'name'; sortDir = 1; }
      setFocus(null);
    }));
    filterEl.addEventListener('input', drawTable);
    root.querySelector('.mx-collapse').addEventListener('click', () => { side.classList.toggle('min'); });

    function setFocus(f) {
      focus = f;
      focusEl.style.display = f ? 'flex' : 'none';
      if (f) focusEl.querySelector('span').textContent = `${f.label}: ${f.nodes.size} device${f.nodes.size === 1 ? '' : 's'}`;
      drawTable(); paint();
    }
    focusEl.querySelector('button').addEventListener('click', () => { legendFilter = null; drawLegend(); setFocus(null); });
    root.querySelector('.mx-tools').addEventListener('click', (e) => {
      const b = e.target.closest('button');
      if (!b) return;
      if (b.dataset.t === 'okLinks') { showOk = !showOk; b.classList.toggle('on', showOk); paint(); }
      if (b.dataset.t === 'top') fit(true);
      if (b.dataset.t === 'reset') fit(false);
    });
    const onKey = (e) => { if (e.key === 'Escape' && !el.closest('.page[hidden]')) { legendFilter = null; drawLegend(); setFocus(null); } };
    window.addEventListener('keydown', onKey);

    // ---------- hover / click ----------
    const ray = new THREE.Raycaster();
    const mouse = new THREE.Vector2();
    function pick(ev) {
      const r = renderer.domElement.getBoundingClientRect();
      mouse.set(((ev.clientX - r.left) / r.width) * 2 - 1, -((ev.clientY - r.top) / r.height) * 2 + 1);
      ray.setFromCamera(mouse, camera);
      const hits = ray.intersectObjects([mesh, ...tubeMeshes], false);
      if (!hits.length) return null;
      const h = hits[0];
      return h.object === mesh ? { n: nodes[h.instanceId] } : { l: h.object.userData.link };
    }
    const lspan = (l) => `<span class="${l.up === 0 ? 'b' : l.up < l.count ? 'p' : ''}">${l.up}/${l.count} up</span>`;
    function tipHtml(hit) {
      if (hit.l) {
        const l = hit.l;
        return `<div class="id">${l.a} ↔ ${l.b}</div>${kit.siteName(kit.device(l.a).site)} ↔ ${kit.siteName(kit.device(l.b).site)}<br>${lspan(l)} · ${l.speed_gbps ?? '?'}G`;
      }
      const d = hit.n.d;
      const ls = kit.linksOf(d.id);
      const badL = ls.filter(isBad);
      const where = [kit.siteName(d.site), TIER_NAME[d.tier] || d.tier, d.pod != null ? 'pod ' + d.pod : '', d.plane != null ? 'plane ' + d.plane : '', d.row != null ? `row ${d.row} col ${d.col}` : ''].filter(Boolean).join(' · ');
      const lines = badL.slice(0, 10).map((l) => `&nbsp;${RANK[kit.device(other(l, d.id)).tier] > RANK[d.tier] ? '↑' : RANK[kit.device(other(l, d.id)).tier] < RANK[d.tier] ? '↓' : '↔'} ${other(l, d.id)}: ${lspan(l)}`);
      return `<div class="id">${d.id}</div>${where}${d.drained ? ' · <span class="d">drained</span>' : ''}<br>` +
        `${ls.length} links in all · <span class="b">${ls.filter((l) => l.up === 0).length} broken</span> · <span class="p">${ls.filter((l) => l.up > 0 && l.up < l.count).length} partly</span>` +
        (lines.length ? '<br>' + lines.join('<br>') : '') + (badL.length > 10 ? `<br>&nbsp;…and ${badL.length - 10} more` : '');
    }
    let downAt = null;
    renderer.domElement.addEventListener('pointermove', (ev) => {
      const hit = pick(ev);
      if (!hit) { tip.style.display = 'none'; renderer.domElement.style.cursor = ''; return; }
      renderer.domElement.style.cursor = 'pointer';
      tip.innerHTML = tipHtml(hit);
      tip.style.display = 'block';
      const r = view.getBoundingClientRect();
      let x = ev.clientX - r.left + 14, y = ev.clientY - r.top + 14;
      if (x + tip.offsetWidth > r.width - 8) x = ev.clientX - r.left - tip.offsetWidth - 14;
      if (y + tip.offsetHeight > r.height - 8) y = ev.clientY - r.top - tip.offsetHeight - 14;
      tip.style.left = x + 'px'; tip.style.top = y + 'px';
    });
    renderer.domElement.addEventListener('pointerleave', () => { tip.style.display = 'none'; });
    renderer.domElement.addEventListener('pointerdown', (ev) => { downAt = [ev.clientX, ev.clientY]; });
    renderer.domElement.addEventListener('pointerup', (ev) => {
      if (!downAt || Math.hypot(ev.clientX - downAt[0], ev.clientY - downAt[1]) > 4) return;
      const hit = pick(ev);
      if (hit && hit.n) kit.select(hit.n.id);
      else if (selected) { selected = null; paint(); }
    });

    kit.onSelect((id) => { selected = id; paint(); });
    kit.onSearch((q) => {
      if (byId.has(q)) return;
      const s = q.toLowerCase();
      const ids = new Set(nodes.filter((n) => n.id.toLowerCase().includes(s) || kit.siteName(n.d.site).toLowerCase() === s).map((n) => n.id));
      setFocus(ids.size ? { key: '?' + q, label: `Search "${q}"`, nodes: ids, links: new Set(links.filter((l) => ids.has(l.a) || ids.has(l.b))) } : null);
    });

    drawLegend();
    drawTable();
    paint();
    size();

    return {
      resize: size,
      cleanup() {
        ro.disconnect();
        window.removeEventListener('keydown', onKey);
        controls.dispose();
        for (const c of linkGroup.children) { c.geometry.dispose(); c.material.dispose(); }
        for (const d of disposables) d.dispose && d.dispose();
        mesh.dispose();
        renderer.dispose();
      },
    };
  }
  // ===== end of shared engine =====

  function layout(el, model, kit) {
      // Site page: for each site, a plate per plane holding its super-spines, the border routers above them,
      // and the backbone routers on top. Links: super-spine -> border -> backbone router (inside the site).
      const T = (t) => kit.devicesByTier(t);
      const supers = T('super_spine'), borders = T('border'), bbrs = T('backbone_router');
      const all = [...supers, ...borders, ...bbrs];
      const ids = new Set(all.map((d) => d.id));
      const sameSite = (l) => kit.device(l.a).site === kit.device(l.b).site;
      const scoped = model.links.filter((l) => ids.has(l.a) && ids.has(l.b) && sameSite(l));
      const sites = model.sites.filter((s) => all.some((d) => d.site === s.code));
      const BORDER_Y = 6, BBR_Y = 11, SS_PITCH = 1.5, PLANE_GAP = 1.6;
      const aspect = (el.clientWidth || window.innerWidth - 480) / (el.clientHeight || window.innerHeight - 60);
      const blocks = sites.map((s) => {
        const ss = supers.filter((d) => d.site === s.code);
        const planes = uniq(ss.map((d) => d.plane)).sort(byNum);
        const perPlane = planes.map((pl) => ss.filter((d) => d.plane === pl).sort((a, b) => d3.ascending(a.id, b.id)));
        const planeW = perPlane.map((r) => Math.max(r.length, 1) * SS_PITCH + 0.6);
        const w = Math.max(d3.sum(planeW) + PLANE_GAP * (planes.length - 1), 6);
        return { s, planes, perPlane, planeW, w, d: 4, h: BBR_Y + 2,
          br: borders.filter((d) => d.site === s.code).sort((a, b) => d3.ascending(a.id, b.id)),
          bb: bbrs.filter((d) => d.site === s.code).sort((a, b) => d3.ascending(a.id, b.id)) };
      });
      arrangeBlocks(blocks, aspect, 5, BBR_Y * 1.7);
      const nodes = [], plates = [], labels = [];
      for (const b of blocks) {
        const cx = b.ox + b.w / 2, cz = b.oz + b.d / 2;
        let x = b.ox + (b.w - (d3.sum(b.planeW) + PLANE_GAP * (b.planes.length - 1))) / 2;
        b.planes.forEach((pl, i) => {
          const pw = b.planeW[i], px = x + pw / 2;
          plates.push({ x: px, z: cz, w: pw, d: 2.2 });
          labels.push({ text: pl == null ? 'Super-spines' : 'Plane ' + pl, p: [px, 0.02, cz + 1.6], h: 0.7, color: '#2f6feb', flat: true });
          b.perPlane[i].forEach((d, k) => nodes.push({ id: d.id, p: [rowX(k, b.perPlane[i].length, px, SS_PITCH, pw - 0.8), 0.4, cz], s: [1.0, 0.8, 0.9] }));
          x += pw + PLANE_GAP;
        });
        b.br.forEach((d, k) => {
          const p = [rowX(k, b.br.length, cx, Math.max(4, b.w / (b.br.length + 1)), b.w - 1), BORDER_Y, cz];
          nodes.push({ id: d.id, p, s: [1.6, 0.9, 1.2] });
          labels.push({ text: d.id.replace(d.site + '-', ''), p: [p[0], BORDER_Y + 1, cz], h: 0.55, color: '#3b4656', weight: 600 });
        });
        b.bb.forEach((d, k) => {
          const p = [rowX(k, b.bb.length, cx, Math.max(4, b.w / (b.bb.length + 1)), b.w - 1), BBR_Y, cz];
          nodes.push({ id: d.id, p, s: [1.8, 1.1, 1.4] });
          labels.push({ text: d.id.replace(d.site + '-', ''), p: [p[0], BBR_Y + 1.1, cz], h: 0.55, color: '#3b4656', weight: 600 });
        });
        labels.push({ text: b.s.name, p: [cx, BBR_Y + 2.6, cz], h: 1.5 });
      }
      const groupOf = (key, label, sk, devs, find) => {
        const s = new Set(devs.map((d) => d.id));
        return { key, label, sk, nodes: s, find, links: scoped.filter((l) => s.has(l.a) || s.has(l.b)) };
      };
      return {
        nodes, plates, labels, links: scoped, deviceWord: 'Super-spines, borders, backbone routers', linkWord: 'Links in the site', elev: 0.7, tube: 0.07,
        groupings: [
          { name: 'Super-spine', title: 'Super-spine (all its links)', kind: 'device',
            groups: () => supers.map((d) => deviceGroup(kit, d, kit.linksOf(d.id))) },
          { name: 'Border', title: 'Border router', kind: 'device',
            groups: () => borders.map((d) => deviceGroup(kit, d, kit.linksOf(d.id))) },
          { name: 'Backbone rtr', title: 'Backbone router (in-site links)', kind: 'device',
            groups: () => bbrs.map((d) => deviceGroup(kit, d, kit.linksOf(d.id).filter(sameSite))) },
          { name: 'Plane', title: 'Plane (super-spine ↔ border links)',
            groups: () => d3.groups(supers, (d) => d.site + '|' + d.plane).map(([k, ds]) =>
              groupOf(k, `${kit.siteName(ds[0].site)} · Plane ${ds[0].plane}`, [ds[0].site, ds[0].plane ?? -1], ds)) },
          { name: 'Site', title: 'Site (links shown here)',
            groups: () => sites.map((s) => groupOf(s.code, s.name, [s.code], all.filter((d) => d.site === s.code))) },
        ],
      };
  }

  return {
    resize() { if (current) current.resize(); },
    mount(el, model, kit) {
      if (current) current.cleanup();
      current = engine(el, model, kit, layout(el, model, kit));
    },
  };
});
