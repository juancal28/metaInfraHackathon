// Racks page. This is your file; nobody else edits it.
// 3D hall floors: every rack at its row/col, empty slots where racks are missing, spines floating above each pod
// with the rack uplinks drawn to them. A side table groups racks by pod, row, site or spine and sorts by any column.
// Everything is computed from the loaded topology; nothing about sizes or counts is hard-coded.

kit.page('racks', function () {
  let cleanup = null;
  let doResize = null;

  return {
    resize() { if (doResize) doResize(); },
    mount(el, model, kit) {
      if (cleanup) cleanup();

      // ---------- palette ----------
      const C = {
        bg: 0xf4f6fa, floor: 0xe6eaf0, floorEdge: 0xc9d1db, empty: 0x6e7781,
        ok: 0x7cc6a0, okCap: 0x4fa57b, partial: 0xf0a020, broken: 0xd1242f, drained: 0x8250df,
        spine: 0x3b4656, select: 0x1f6feb, dim: 0xe9ecf1,
        lineOk: 0xb8c2cf,
      };
      const css = (n) => '#' + n.toString(16).padStart(6, '0');

      // ---------- data ----------
      const racks = kit.devicesByTier('top_of_rack').filter((d) => d.row != null && d.col != null);
      const spines = kit.devicesByTier('spine');
      const sites = model.sites.filter((s) => racks.some((r) => r.site === s.code));
      const other = (l, id) => (l.a === id ? l.b : l.a);

      const info = new Map(); // rack id -> stats
      for (const r of racks) {
        const ups = kit.uplinks(r.id);
        const broken = ups.filter((l) => l.up === 0);
        const partial = ups.filter((l) => l.up > 0 && l.up < l.count);
        const status = broken.length ? 'broken' : partial.length ? 'partial' : 'ok';
        info.set(r.id, { d: r, ups, broken, partial, status });
      }

      // ---------- layout ----------
      const PX = 1.0, PZ = 1.5, POD_GAP = 1.4, SITE_GAP = 6, SPINE_Y = 7;
      const siteLayout = new Map();
      for (const s of sites) {
        const rs = racks.filter((r) => r.site === s.code);
        const minCol = d3.min(rs, (r) => r.col), maxCol = d3.max(rs, (r) => r.col);
        const minRow = d3.min(rs, (r) => r.row), maxRow = d3.max(rs, (r) => r.row);
        // dominant pod per row, to open an aisle gap between pods
        const rowPod = new Map();
        for (let row = minRow; row <= maxRow; row++) {
          const inRow = rs.filter((r) => r.row === row);
          rowPod.set(row, inRow.length ? d3.mode(inRow, (r) => r.pod) : null);
        }
        // a row with no racks at all belongs to the pod around it; on a pod boundary, to the pod with fewer rows
        const podRowsN = d3.rollup([...rowPod.values()].filter((p) => p != null), (v) => v.length, (p) => p);
        let last = null;
        for (let row = minRow; row <= maxRow; row++) {
          if (rowPod.get(row) != null) { last = rowPod.get(row); continue; }
          let next = null;
          for (let r2 = row + 1; r2 <= maxRow && next == null; r2++) next = rowPod.get(r2);
          let pick = last ?? next;
          if (last != null && next != null && last !== next && (podRowsN.get(next) || 0) < (podRowsN.get(last) || 0)) pick = next;
          rowPod.set(row, pick);
          podRowsN.set(pick, (podRowsN.get(pick) || 0) + 1);
        }
        const rowZ = new Map();
        let z = 0, prevPod;
        for (let row = minRow; row <= maxRow; row++) {
          const p = rowPod.get(row);
          if (row > minRow && p != null && prevPod != null && p !== prevPod) z += POD_GAP;
          rowZ.set(row, z);
          z += PZ;
          if (p != null) prevPod = p;
        }
        const w = (maxCol - minCol + 1) * PX, dpt = z;
        const occupied = new Set(rs.map((r) => r.row + ',' + r.col));
        const empties = [];
        for (let row = minRow; row <= maxRow; row++)
          for (let col = minCol; col <= maxCol; col++)
            if (!occupied.has(row + ',' + col)) empties.push({ row, col, pod: rowPod.get(row) });
        siteLayout.set(s.code, { s, rs, minCol, maxCol, minRow, maxRow, rowZ, rowPod, w, dpt, empties, ox: 0, oz: 0 });
      }
      // arrange site floors in a grid whose shape best matches the screen
      const aspect = (el.clientWidth || window.innerWidth - 420) / (el.clientHeight || window.innerHeight - 60);
      const L = [...siteLayout.values()];
      const maxW = d3.max(L, (l) => l.w) || 1, maxD = d3.max(L, (l) => l.dpt) || 1;
      let bestCols = 1, bestScore = Infinity;
      for (let c = 1; c <= L.length; c++) {
        const rowsN = Math.ceil(L.length / c);
        const W = c * maxW + (c - 1) * SITE_GAP, D = (rowsN * maxD + (rowsN - 1) * SITE_GAP * 1.6) * 0.75 + SPINE_Y * 0.6;
        const score = Math.max(W / aspect, D);
        if (score < bestScore) { bestScore = score; bestCols = c; }
      }
      L.forEach((l, i) => {
        l.ox = (i % bestCols) * (maxW + SITE_GAP);
        l.oz = Math.floor(i / bestCols) * (maxD + SITE_GAP * 1.6);
      });
      const pos = (site, row, col) => {
        const l = siteLayout.get(site);
        return new THREE.Vector3(l.ox + (col - l.minCol + 0.5) * PX, 0, l.oz + l.rowZ.get(row) + PZ / 2);
      };

      // spines float above the middle of their pod's racks
      const spinePos = new Map();
      const podsBySite = d3.group(racks, (r) => r.site, (r) => r.pod);
      for (const [site, pods] of podsBySite) {
        const l = siteLayout.get(site);
        for (const [pod, rs] of pods) {
          const sp = spines.filter((s) => s.site === site && s.pod === pod)
            .sort((a, b) => (a.plane ?? 0) - (b.plane ?? 0) || d3.ascending(a.id, b.id));
          const zc = d3.mean(rs, (r) => pos(site, r.row, r.col).z);
          const span = l.w * 0.55;
          sp.forEach((s, i) => {
            const x = l.ox + l.w / 2 + (sp.length === 1 ? 0 : (i / (sp.length - 1) - 0.5) * span);
            spinePos.set(s.id, new THREE.Vector3(x, SPINE_Y, zc));
          });
        }
      }
      // spines with no racks (shouldn't happen) are simply not drawn on this page

      // ---------- DOM ----------
      el.innerHTML = '';
      const root = document.createElement('div');
      root.className = 'rk-root';
      root.innerHTML = `
        <style>
          .rk-root{position:absolute;inset:0;display:flex;font-size:12px}
          .rk-view{position:relative;flex:1;min-width:0;background:${css(C.bg)}}
          .rk-view canvas{display:block}
          .rk-side{width:clamp(280px,36%,460px);flex:none;display:flex;flex-direction:column;border-left:1px solid var(--border);background:#fff;min-height:0}
          .rk-side.min{width:36px}.rk-side.min>*:not(.rk-collapse){display:none}
          .rk-head{padding:10px 12px 6px;display:flex;flex-wrap:wrap;gap:6px;align-items:center}
          .rk-head b{font-size:13px;margin-right:auto}
          .rk-seg{display:inline-flex;background:#eef1f5;border-radius:8px;padding:2px}
          .rk-seg button{border:0;background:none;padding:3px 9px;border-radius:6px;cursor:pointer;color:var(--muted);font-size:12px}
          .rk-seg button.on{background:#fff;color:var(--accent);font-weight:600;box-shadow:0 1px 2px rgba(0,0,0,.12)}
          .rk-filter{width:100%;padding:5px 8px;border:1px solid var(--border);border-radius:7px;font:inherit}
          .rk-tablewrap{flex:1;overflow:auto;min-height:0;border-top:1px solid var(--border)}
          .rk-table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
          .rk-table th{position:sticky;top:0;background:#f6f8fa;color:var(--muted);font-weight:600;padding:5px 4px;text-align:right;cursor:pointer;user-select:none;border-bottom:1px solid var(--border);white-space:nowrap;font-size:11px}
          .rk-table th:first-child,.rk-table td:first-child{text-align:left;padding-left:10px;white-space:nowrap}
          .rk-table th.sorted{color:var(--accent)}
          .rk-table td{padding:3px 4px;text-align:right;border-bottom:1px solid #f0f2f5;cursor:pointer}
          .rk-table tr:hover td{background:#f3f7ff}
          .rk-table tr.on td{background:var(--accent-soft)}
          .rk-table tr.total td{font-weight:700;background:#fafbfc;cursor:default}
          .rk-table td.z{color:#c3c9d1}
          .rk-table td.hot-broken{color:${css(C.broken)};font-weight:700}
          .rk-table td.hot-partial{color:#b26b00;font-weight:700}
          .rk-table td.hot-drained{color:${css(C.drained)};font-weight:700}
          .rk-legend{position:absolute;left:10px;right:10px;bottom:8px;display:flex;flex-wrap:wrap;align-items:center;gap:2px 4px;background:rgba(255,255,255,.94);border:1px solid var(--border);border-radius:10px;padding:5px 8px;box-shadow:0 2px 8px rgba(0,0,0,.06)}
          .rk-legend .t{font-weight:700;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.06em;margin:0 2px 0 6px}
          .rk-legend .i{display:flex;align-items:center;gap:6px;padding:2px 6px;border-radius:6px;cursor:pointer}
          .rk-legend .br{flex-basis:100%;height:0}
          .rk-legend .i:hover{background:#eef1f5}.rk-legend .i.on{background:var(--accent-soft);font-weight:600}
          .rk-legend .i .n{margin-left:auto;padding-left:10px;color:var(--muted);font-variant-numeric:tabular-nums}
          .rk-sw{width:14px;height:11px;border-radius:2px;flex:none}
          .rk-ln{width:22px;height:0;flex:none;border-top:3px solid}
          .rk-tools{position:absolute;right:10px;top:10px;display:flex;gap:6px}
          .rk-tools button,.rk-collapse{border:1px solid var(--border);background:#fff;border-radius:7px;padding:4px 9px;cursor:pointer;font-size:12px;color:var(--text)}
          .rk-tools button.on{background:var(--accent-soft);color:var(--accent);border-color:#b6cdf8}
          .rk-collapse{margin:8px 6px 0 auto;padding:3px 7px}
          .rk-tip{position:absolute;pointer-events:none;background:rgba(24,28,34,.94);color:#fff;border-radius:8px;padding:7px 9px;font-size:12px;line-height:1.45;display:none;white-space:nowrap;z-index:5}
          .rk-tip .id{font-family:ui-monospace,Menlo,monospace;font-weight:700}
          .rk-tip .b{color:#ff8a8f}.rk-tip .p{color:#ffc65c}.rk-tip .d{color:#c8a6ff}
          .rk-focus{position:absolute;left:50%;top:10px;transform:translateX(-50%);background:var(--accent);color:#fff;border-radius:999px;padding:4px 6px 4px 12px;display:none;align-items:center;gap:8px;font-weight:600;box-shadow:0 2px 6px rgba(47,111,235,.3)}
          .rk-focus button{border:0;background:rgba(255,255,255,.25);color:#fff;border-radius:999px;padding:1px 8px;cursor:pointer}
          .rk-hint{position:absolute;left:12px;top:12px;max-width:calc(100% - 360px);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:#8c959f;font-size:11px}
        </style>
        <div class="rk-view">
          <div class="rk-tools">
            <button data-t="okLinks" class="on" title="Show healthy uplinks too">Healthy uplinks</button>
            <button data-t="top" title="Look straight down">Top view</button>
            <button data-t="reset">Reset view</button>
          </div>
          <div class="rk-focus"><span></span><button title="Clear (Esc)">✕</button></div>
          <div class="rk-legend"></div>
          <div class="rk-hint">Drag to rotate · scroll to zoom · right-drag to pan · click a rack to select</div>
          <div class="rk-tip"></div>
        </div>
        <div class="rk-side">
          <button class="rk-collapse" title="Hide or show the table">⇥</button>
          <div class="rk-head">
            <b>Group racks by</b>
            <span class="rk-seg">
              <button data-g="pod" class="on">Pod</button><button data-g="row">Row</button><button data-g="site">Site</button><button data-g="spine">Spine</button>
            </span>
            <input class="rk-filter" type="search" placeholder="Filter groups (e.g. site name, pod 3, spine2)">
          </div>
          <div class="rk-tablewrap"><table class="rk-table"></table></div>
          <div class="note" style="padding:6px 10px">Click a column to sort · click a group to highlight it on the floor</div>
        </div>`;
      el.appendChild(root);
      const view = root.querySelector('.rk-view');
      const tip = root.querySelector('.rk-tip');
      const legendEl = root.querySelector('.rk-legend');
      const focusEl = root.querySelector('.rk-focus');
      const side = root.querySelector('.rk-side');
      const tableEl = root.querySelector('.rk-table');
      const filterEl = root.querySelector('.rk-filter');

      // ---------- three.js scene ----------
      const renderer = new THREE.WebGLRenderer({ antialias: true });
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      renderer.setClearColor(C.bg);
      view.prepend(renderer.domElement);
      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 5000);
      const controls = new THREE.OrbitControls(camera, renderer.domElement);
      controls.enableDamping = false;
      controls.maxPolarAngle = Math.PI / 2 - 0.02;
      scene.add(new THREE.HemisphereLight(0xffffff, 0xb8c0cc, 1.6));
      const sun = new THREE.DirectionalLight(0xffffff, 1.4);
      sun.position.set(-30, 60, 40);
      scene.add(sun);
      const disposables = [];
      const track = (o) => { disposables.push(o); return o; };

      // floors, empty slots, labels
      const emptyPts = [];
      const S = 0.38; // half-size of an empty slot outline
      for (const l of siteLayout.values()) {
        const floor = new THREE.Mesh(track(new THREE.BoxGeometry(l.w + 1.6, 0.2, l.dpt + 1.6)),
          track(new THREE.MeshLambertMaterial({ color: C.floor })));
        floor.position.set(l.ox + l.w / 2, -0.11, l.oz + l.dpt / 2);
        scene.add(floor);
        const edge = new THREE.LineSegments(track(new THREE.EdgesGeometry(floor.geometry)), track(new THREE.LineBasicMaterial({ color: C.floorEdge })));
        edge.position.copy(floor.position);
        scene.add(edge);
        for (const e of l.empties) {
          const p = pos(l.s.code, e.row, e.col);
          const x0 = p.x - S, x1 = p.x + S, z0 = p.z - S * 0.8, z1 = p.z + S * 0.8, y = 0.01;
          emptyPts.push(x0, y, z0, x1, y, z0, x1, y, z0, x1, y, z1, x1, y, z1, x0, y, z1, x0, y, z1, x0, y, z0, x0, y, z0, x1, y, z1);
        }
        addLabel(l.s.name, l.ox + l.w / 2, 0.2, l.oz - 2.2, 2.0, '#1f2328', 700);
        // pod labels on the left edge, row numbers on the right edge
        const podRows = d3.group([...l.rowPod.entries()].filter(([, p]) => p != null), ([, p]) => p);
        for (const [pod, rows] of podRows) {
          const zs = rows.map(([row]) => l.oz + l.rowZ.get(row) + PZ / 2);
          addLabel('Pod ' + pod, l.ox - 1.9, 0.05, d3.mean(zs), 0.85, '#2f6feb', 700);
        }
        for (let row = l.minRow; row <= l.maxRow; row++)
          addLabel('R' + row, l.ox + l.w + 0.8, 0.05, l.oz + l.rowZ.get(row) + PZ / 2, 0.5, '#8c959f', 600);
      }
      if (emptyPts.length) {
        const g = track(new THREE.BufferGeometry());
        g.setAttribute('position', new THREE.Float32BufferAttribute(emptyPts, 3));
        const m = track(new THREE.LineDashedMaterial({ color: C.empty, dashSize: 0.12, gapSize: 0.08 }));
        const ls = new THREE.LineSegments(g, m);
        ls.computeLineDistances();
        scene.add(ls);
        // faint dark fill so a missing rack reads as a hole in the row
        const all = L.flatMap((l) => l.empties.map((e) => pos(l.s.code, e.row, e.col)));
        const fill = new THREE.InstancedMesh(track(new THREE.PlaneGeometry(S * 2, S * 1.6)), track(new THREE.MeshBasicMaterial({ color: 0xcfd6df })), all.length);
        const q = new THREE.Quaternion().setFromEuler(new THREE.Euler(-Math.PI / 2, 0, 0)), one = new THREE.Vector3(1, 1, 1);
        all.forEach((p, i) => fill.setMatrixAt(i, new THREE.Matrix4().compose(new THREE.Vector3(p.x, 0.005, p.z), q, one)));
        scene.add(fill);
        disposables.push(fill);
      }

      function addLabel(text, x, y, z, h, color, weight) {
        const c = document.createElement('canvas');
        const ctx = c.getContext('2d');
        const fs = 64;
        ctx.font = `${weight} ${fs}px -apple-system, Segoe UI, Roboto, sans-serif`;
        c.width = Math.ceil(ctx.measureText(text).width) + 16; c.height = fs + 16;
        ctx.font = `${weight} ${fs}px -apple-system, Segoe UI, Roboto, sans-serif`;
        ctx.fillStyle = color; ctx.textBaseline = 'middle'; ctx.textAlign = 'center';
        ctx.fillText(text, c.width / 2, c.height / 2);
        const tex = track(new THREE.CanvasTexture(c));
        tex.anisotropy = 4;
        const mat = track(new THREE.MeshBasicMaterial({ map: tex, transparent: true, depthWrite: false }));
        const mesh = new THREE.Mesh(track(new THREE.PlaneGeometry(h * c.width / c.height, h)), mat);
        mesh.rotation.x = -Math.PI / 2;
        mesh.position.set(x, y, z);
        scene.add(mesh);
      }

      // racks: body + cap (cap shows uplink state, body shows drained or uplink state)
      const RW = 0.72, RD = 0.95, RH = 1.0;
      const bodyGeo = track(new THREE.BoxGeometry(RW, 1, RD));
      const capGeo = track(new THREE.BoxGeometry(RW + 0.06, 0.16, RD + 0.06));
      const bodies = new THREE.InstancedMesh(bodyGeo, track(new THREE.MeshLambertMaterial()), Math.max(racks.length, 1));
      const caps = new THREE.InstancedMesh(capGeo, track(new THREE.MeshLambertMaterial()), Math.max(racks.length, 1));
      bodies.count = caps.count = racks.length;
      scene.add(bodies, caps);
      const rackTop = new Map();
      const heightOf = (st) => (st === 'broken' ? 1.7 : st === 'partial' ? 1.35 : RH);
      const mtx = new THREE.Matrix4();
      racks.forEach((r, i) => {
        const p = pos(r.site, r.row, r.col);
        const h = heightOf(info.get(r.id).status);
        mtx.compose(new THREE.Vector3(p.x, h / 2, p.z), new THREE.Quaternion(), new THREE.Vector3(1, h, 1));
        bodies.setMatrixAt(i, mtx);
        mtx.makeTranslation(p.x, h + 0.08, p.z);
        caps.setMatrixAt(i, mtx);
        rackTop.set(r.id, new THREE.Vector3(p.x, h + 0.16, p.z));
      });

      // spines
      const spineList = spines.filter((s) => spinePos.has(s.id));
      const spineMesh = new THREE.InstancedMesh(track(new THREE.BoxGeometry(1.1, 0.5, 0.8)), track(new THREE.MeshLambertMaterial()), Math.max(spineList.length, 1));
      spineMesh.count = spineList.length;
      spineList.forEach((s, i) => { mtx.makeTranslation(spinePos.get(s.id).x, SPINE_Y, spinePos.get(s.id).z); spineMesh.setMatrixAt(i, mtx); });
      scene.add(spineMesh);
      for (const s of spineList) {
        const p = spinePos.get(s.id);
        addLabel(s.id.replace(/^.*-(?=spine)/, ''), p.x, SPINE_Y + 0.6, p.z, 0.45, '#3b4656', 600);
      }

      // uplink lines (rebuilt when the focus changes)
      const lineGroup = new THREE.Group();
      scene.add(lineGroup);

      // ---------- state ----------
      let showOkLinks = true;
      let focus = null; // { label, ids:Set, spine? }
      let legendFilter = null; // 'broken' | 'partial' | 'drained' | 'ok' | 'empty'
      let selected = kit.selected;
      let groupBy = 'pod', sortCol = 'name', sortDir = 1;

      const legendMatch = (id) => {
        if (!legendFilter) return true;
        const x = info.get(id);
        if (legendFilter === 'drained') return x.d.drained;
        if (legendFilter === 'broken') return x.broken.length > 0;
        if (legendFilter === 'partial') return x.partial.length > 0;
        if (legendFilter === 'ok') return x.status === 'ok' && !x.d.drained;
        return false;
      };
      const isLit = (id) => (!focus || focus.ids.has(id)) && legendMatch(id);
      const anyFilter = () => !!(focus || legendFilter);

      const col = new THREE.Color(), dimC = new THREE.Color(C.dim);
      function paint() {
        racks.forEach((r, i) => {
          const x = info.get(r.id);
          const lit = isLit(r.id);
          const stCol = x.status === 'broken' ? C.broken : x.status === 'partial' ? C.partial : C.ok;
          const capCol = x.status === 'ok' ? C.okCap : stCol;
          col.set(r.id === selected ? C.select : r.drained ? C.drained : stCol);
          if (!lit && r.id !== selected) col.lerp(dimC, 0.85);
          bodies.setColorAt(i, col);
          col.set(r.id === selected ? C.select : capCol);
          if (!lit && r.id !== selected) col.lerp(dimC, 0.85);
          caps.setColorAt(i, col);
        });
        spineList.forEach((s, i) => {
          col.set(s.id === selected || (focus && focus.spine === s.id) ? C.select : s.drained ? C.drained : C.spine);
          if (anyFilter() && !(focus && focus.spine === s.id) && s.id !== selected && !racks.some((r) => isLit(r.id) && info.get(r.id).ups.some((l) => other(l, r.id) === s.id))) col.lerp(dimC, 0.8);
          spineMesh.setColorAt(i, col);
        });
        if (bodies.instanceColor) bodies.instanceColor.needsUpdate = true;
        if (caps.instanceColor) caps.instanceColor.needsUpdate = true;
        if (spineMesh.instanceColor) spineMesh.instanceColor.needsUpdate = true;
        buildLines();
        render();
      }

      function buildLines() {
        for (const c of [...lineGroup.children]) { c.geometry.dispose(); c.material.dispose(); lineGroup.remove(c); }
        const ok = [], part = [], brk = [], sel = [];
        for (const r of racks) {
          const x = info.get(r.id);
          const lit = isLit(r.id);
          for (const l of x.ups) {
            const sid = other(l, r.id);
            const sp = spinePos.get(sid);
            if (!sp) continue;
            if (focus && focus.spine && focus.spine !== sid) continue;
            const a = rackTop.get(r.id);
            const seg = [a.x, a.y, a.z, sp.x, sp.y - 0.25, sp.z];
            if (r.id === selected || sid === selected) { sel.push(...seg); if (l.up === l.count) continue; }
            if (!lit && anyFilter()) continue;
            if (l.up === 0) brk.push(...seg);
            else if (l.up < l.count) part.push(...seg);
            else if (showOkLinks) ok.push(...seg);
          }
        }
        const add = (pts, mat, dashed) => {
          if (!pts.length) return;
          const g = new THREE.BufferGeometry();
          g.setAttribute('position', new THREE.Float32BufferAttribute(pts, 3));
          const ls = new THREE.LineSegments(g, mat);
          if (dashed) ls.computeLineDistances();
          lineGroup.add(ls);
        };
        add(ok, new THREE.LineBasicMaterial({ color: C.lineOk, transparent: true, opacity: anyFilter() ? 0.5 : 0.22, depthWrite: false }));
        add(sel, new THREE.LineBasicMaterial({ color: C.select }));
        add(part, new THREE.LineDashedMaterial({ color: C.partial, dashSize: 0.35, gapSize: 0.2 }), true);
        add(brk, new THREE.LineBasicMaterial({ color: C.broken }));
      }

      // ---------- camera fit ----------
      const bbox = new THREE.Box3();
      for (const l of siteLayout.values()) {
        bbox.expandByPoint(new THREE.Vector3(l.ox - 2.6, 0, l.oz - 3));
        bbox.expandByPoint(new THREE.Vector3(l.ox + l.w + 1.5, SPINE_Y + 1, l.oz + l.dpt + 0.8));
      }
      if (bbox.isEmpty()) bbox.set(new THREE.Vector3(-1, 0, -1), new THREE.Vector3(1, 1, 1));
      function fit(top) {
        const center = bbox.getCenter(new THREE.Vector3());
        center.y = top ? 0 : 1.5;
        const dir = top ? new THREE.Vector3(0, 1, 0.0001).normalize() : new THREE.Vector3(0, Math.sin(0.95), Math.cos(0.95));
        const corners = [];
        for (const x of [bbox.min.x, bbox.max.x]) for (const y of [bbox.min.y, bbox.max.y]) for (const z of [bbox.min.z, bbox.max.z]) corners.push(new THREE.Vector3(x, y, z));
        // keep the floors clear of the legend: shift the projection centre right by the legend's width
        const lh = Math.min(legendEl.offsetHeight + 16, H * 0.3);
        camera.setViewOffset(W, H + lh, 0, 0, W, H);
        const minY = -1 + (2 * lh) / H + 0.02;
        let lo = 1, hi = 5000;
        for (let k = 0; k < 40; k++) {
          const d = (lo + hi) / 2;
          camera.position.copy(center).addScaledVector(dir, d);
          camera.lookAt(center);
          camera.updateMatrixWorld();
          const ok = corners.every((c) => { const v = c.clone().project(camera); return Math.abs(v.x) < 0.96 && v.y > minY && v.y < 0.88 && v.z < 1; });
          if (ok) hi = d; else lo = d;
        }
        camera.position.copy(center).addScaledVector(dir, hi);
        controls.target.copy(center);
        controls.update();
        render();
      }

      let W = 0, H = 0;
      function size() {
        const w = view.clientWidth, h = view.clientHeight;
        if (!w || !h) return false;
        if (w === W && h === H) return true;
        const first = !W;
        W = w; H = h;
        renderer.setSize(w, h);
        camera.aspect = w / (h + Math.min(legendEl.offsetHeight + 16, h * 0.3));
        fit(false);
        if (first) render();
        return true;
      }
      let raf = 0;
      function render() {
        if (raf) return;
        raf = requestAnimationFrame(() => { raf = 0; renderer.render(scene, camera); });
      }
      controls.addEventListener('change', render);
      const ro = new ResizeObserver(() => size());
      ro.observe(view);
      doResize = () => size();

      // ---------- legend ----------
      const counts = {
        ok: racks.filter((r) => info.get(r.id).status === 'ok' && !r.drained).length,
        partial: racks.filter((r) => info.get(r.id).partial.length).length,
        broken: racks.filter((r) => info.get(r.id).broken.length).length,
        drained: racks.filter((r) => r.drained).length,
        empty: d3.sum(L, (l) => l.empties.length),
      };
      function drawLegend() {
        const item = (k, sw, label) => `<div class="i ${legendFilter === k ? 'on' : ''}" data-k="${k}">${sw}<span>${label}</span><span class="n">${counts[k]}</span></div>`;
        const box = (c, h) => `<span class="rk-sw" style="background:${css(c)};height:${h}px"></span>`;
        legendEl.innerHTML =
          `<div class="t">Racks · click to filter</div>` +
          item('ok', box(C.ok, 9), 'All uplinks up') +
          item('partial', box(C.partial, 12), 'Has a partly broken uplink') +
          item('broken', box(C.broken, 15), 'Has a broken uplink (taller)') +
          item('drained', box(C.drained, 11), 'Drained rack (cap = uplink state)') +
          `<div class="i" data-k="empty" style="cursor:default"><span class="rk-sw" style="border:1.5px dashed ${css(C.empty)};background:none"></span><span>Missing rack (empty slot)</span><span class="n">${counts.empty}</span></div>` +
          `<div class="br"></div><div class="t">Uplinks to spines</div>` +
          `<div class="i" style="cursor:default"><span class="rk-ln" style="border-color:${css(C.lineOk)}"></span>Up</div>` +
          `<div class="i" style="cursor:default"><span class="rk-ln" style="border-top-style:dashed;border-color:${css(C.partial)}"></span>Partly broken (some parallel links down)</div>` +
          `<div class="i" style="cursor:default"><span class="rk-ln" style="border-color:${css(C.broken)}"></span>Broken (all down)</div>` +
          `<div class="i" style="cursor:default"><span class="rk-sw" style="background:${css(C.spine)}"></span>Spine &nbsp;<span class="rk-sw" style="background:${css(C.drained)}"></span>Drained spine</div>`;
      }
      legendEl.addEventListener('click', (e) => {
        const it = e.target.closest('.i[data-k]');
        if (!it || it.dataset.k === 'empty') return;
        legendFilter = legendFilter === it.dataset.k ? null : it.dataset.k;
        drawLegend(); drawTable(); paint();
      });

      // ---------- grouping table ----------
      const siteOrder = new Map(sites.map((s, i) => [s.code, i]));
      function groups() {
        const out = new Map();
        const get = (key, label, sk) => {
          if (!out.has(key)) out.set(key, { key, label, sk, ids: new Set(), racks: 0, empty: 0, bad: 0, broken: 0, partial: 0, drained: 0, down: 0, spine: null });
          return out.get(key);
        };
        if (groupBy === 'spine') {
          for (const s of spineList) {
            const g = get(s.id, s.id, [siteOrder.get(s.site), s.pod ?? 0, s.plane ?? 0, s.id]);
            g.spine = s.id; g.find = kit.siteName(s.site);
          }
          for (const r of racks) for (const l of info.get(r.id).ups) {
            const g = out.get(other(l, r.id));
            if (!g) continue;
            g.ids.add(r.id); g.racks++;
            if (l.up === 0) g.broken++; else if (l.up < l.count) g.partial++;
            if (l.up < l.count) g.bad++;
            if (r.drained) g.drained++;
            g.down += l.count - l.up;
          }
          return [...out.values()];
        }
        const keyOf = (site, pod, row) =>
          groupBy === 'pod' ? [`${site}|${pod}`, `${kit.siteName(site)} · Pod ${pod}`, [siteOrder.get(site), pod ?? -1]]
            : groupBy === 'row' ? [`${site}|${row}`, `${kit.siteName(site)} · Row ${row}`, [siteOrder.get(site), row]]
              : [site, kit.siteName(site), [siteOrder.get(site)]];
        for (const r of racks) {
          const [k, lab, sk] = keyOf(r.site, r.pod, r.row);
          const g = get(k, lab, sk);
          const x = info.get(r.id);
          g.ids.add(r.id); g.racks++;
          if (x.broken.length) g.broken++;
          if (x.partial.length) g.partial++;
          if (x.broken.length || x.partial.length) g.bad++;
          if (r.drained) g.drained++;
          g.down += d3.sum(x.ups, (l) => l.count - l.up);
        }
        for (const l of L) for (const e of l.empties) {
          const [k, lab, sk] = keyOf(l.s.code, e.pod, e.row);
          get(k, lab, sk).empty++;
        }
        return [...out.values()];
      }
      const COLS = () => groupBy === 'spine'
        ? [['name', 'Spine'], ['racks', 'Racks'], ['bad', 'Bad'], ['broken', 'Broken'], ['partial', 'Partly'], ['drained', 'Drained racks'], ['down', 'Down']]
        : [['name', groupBy === 'pod' ? 'Pod' : groupBy === 'row' ? 'Row' : 'Site'], ['racks', 'Racks'], ['empty', 'Empty'], ['bad', 'Bad'], ['broken', 'Broken'], ['partial', 'Partly'], ['drained', 'Drained'], ['down', 'Down']];
      const TITLES = {
        bad: 'Racks with a broken OR partly broken uplink (spine view: uplinks to this spine not fully up)',
        racks: 'Racks in this group', empty: 'Empty slots (missing racks)', drained: 'Drained racks',
        broken: 'Racks with at least one fully broken uplink (spine view: broken uplinks to this spine)',
        partial: 'Racks with at least one partly broken uplink (spine view: partly broken uplinks to this spine)',
        down: 'Individual uplinks that are down (counting parallel links)',
      };
      function cmpName(a, b) {
        for (let i = 0; i < Math.max(a.sk.length, b.sk.length); i++) {
          const c = d3.ascending(a.sk[i], b.sk[i]);
          if (c) return c;
        }
        return 0;
      }
      function drawTable() {
        let gs = groups();
        const q = filterEl.value.trim().toLowerCase();
        if (q) gs = gs.filter((g) => (g.label + ' ' + g.key + ' ' + (g.find || '')).toLowerCase().includes(q));
        gs.sort((a, b) => (sortCol === 'name' ? cmpName(a, b) * sortDir : (b[sortCol] - a[sortCol]) * sortDir || cmpName(a, b)));
        const cols = COLS();
        const cell = (g, k) => {
          if (k === 'name') return `<td>${g.label}</td>`;
          const v = g[k];
          const hot = v && (k === 'broken' || k === 'down' || k === 'bad') ? 'hot-broken' : v && k === 'partial' ? 'hot-partial' : v && k === 'drained' ? 'hot-drained' : v ? '' : 'z';
          return `<td class="${hot}">${v}</td>`;
        };
        const tot = { label: `Total (${gs.length} ${groupBy === 'site' ? 'sites' : groupBy + 's'})` };
        for (const [k] of cols) if (k !== 'name') tot[k] = d3.sum(gs, (g) => g[k]);
        tableEl.innerHTML =
          `<tr>${cols.map(([k, t]) => `<th data-c="${k}" class="${sortCol === k ? 'sorted' : ''}" title="${TITLES[k] || 'Sort by name'}">${t}${sortCol === k ? (sortDir > 0 ? (k === 'name' ? ' ▲' : ' ▼') : (k === 'name' ? ' ▼' : ' ▲')) : ''}</th>`).join('')}</tr>` +
          gs.map((g) => `<tr data-k="${g.key}" class="${focus && focus.key === g.key ? 'on' : ''}">${cols.map(([k]) => cell(g, k)).join('')}</tr>`).join('') +
          `<tr class="total">${cols.map(([k]) => (k === 'name' ? `<td>${tot.label}</td>` : `<td>${tot[k]}</td>`)).join('')}</tr>`;
        tableEl._groups = new Map(gs.map((g) => [g.key, g]));
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
        const g = tableEl._groups.get(tr.dataset.k);
        setFocus(focus && focus.key === g.key ? null : { key: g.key, label: g.label, ids: g.ids, spine: g.spine });
      });
      root.querySelectorAll('.rk-seg button').forEach((b) => b.addEventListener('click', () => {
        root.querySelectorAll('.rk-seg button').forEach((x) => x.classList.toggle('on', x === b));
        groupBy = b.dataset.g;
        filterEl.value = '';
        if (!COLS().some(([k]) => k === sortCol)) { sortCol = 'name'; sortDir = 1; }
        setFocus(null);
      }));
      filterEl.addEventListener('input', drawTable);
      root.querySelector('.rk-collapse').addEventListener('click', () => {
        side.classList.toggle('min');
        size();
      });

      function setFocus(f) {
        focus = f;
        focusEl.style.display = f ? 'flex' : 'none';
        if (f) focusEl.querySelector('span').textContent = `${f.label}: ${f.ids.size} rack${f.ids.size === 1 ? '' : 's'}`;
        drawTable(); paint();
      }
      focusEl.querySelector('button').addEventListener('click', () => { setFocus(null); legendFilter = null; drawLegend(); paint(); });

      // ---------- tools ----------
      root.querySelector('.rk-tools').addEventListener('click', (e) => {
        const b = e.target.closest('button');
        if (!b) return;
        if (b.dataset.t === 'okLinks') { showOkLinks = !showOkLinks; b.classList.toggle('on', showOkLinks); paint(); }
        if (b.dataset.t === 'top') fit(true);
        if (b.dataset.t === 'reset') fit(false);
      });
      const onKey = (e) => {
        if (e.key === 'Escape' && !el.closest('.page[hidden]')) { legendFilter = null; drawLegend(); setFocus(null); }
      };
      window.addEventListener('keydown', onKey);

      // ---------- hover / click ----------
      const ray = new THREE.Raycaster();
      const mouse = new THREE.Vector2();
      function pick(ev) {
        const r = renderer.domElement.getBoundingClientRect();
        mouse.set(((ev.clientX - r.left) / r.width) * 2 - 1, -((ev.clientY - r.top) / r.height) * 2 + 1);
        ray.setFromCamera(mouse, camera);
        const hits = ray.intersectObjects([bodies, caps, spineMesh], false);
        if (!hits.length) return null;
        const h = hits[0];
        return h.object === spineMesh ? spineList[h.instanceId] : racks[h.instanceId];
      }
      function tipHtml(d) {
        if (d.tier === 'spine') {
          const ls = kit.linksOf(d.id).filter((l) => info.has(other(l, d.id)));
          const b = ls.filter((l) => l.up === 0).length, p = ls.filter((l) => l.up > 0 && l.up < l.count).length;
          return `<div class="id">${d.id}</div>Spine · ${kit.siteName(d.site)} · pod ${d.pod}${d.plane != null ? ' · plane ' + d.plane : ''}${d.drained ? ' · <span class="d">drained</span>' : ''}<br>` +
            `Rack downlinks: ${ls.length} · <span class="b">broken ${b}</span> · <span class="p">partly ${p}</span>`;
        }
        const x = info.get(d.id);
        const rows = x.ups.map((l) => {
          const cls = l.up === 0 ? 'b' : l.up < l.count ? 'p' : '';
          return `&nbsp;→ ${other(l, d.id)}: <span class="${cls}">${l.up}/${l.count} up</span> · ${l.speed_gbps ?? '?'}G`;
        });
        return `<div class="id">${d.id}</div>${kit.siteName(d.site)} · pod ${d.pod} · row ${d.row} · col ${d.col}${d.rack != null ? ' · rack ' + d.rack : ''}` +
          `${d.drained ? ' · <span class="d">drained</span>' : ''}<br>Uplinks:<br>${rows.join('<br>') || '&nbsp;none'}`;
      }
      let downAt = null;
      const onMove = (ev) => {
        const d = pick(ev);
        if (!d) { tip.style.display = 'none'; renderer.domElement.style.cursor = ''; return; }
        renderer.domElement.style.cursor = 'pointer';
        tip.innerHTML = tipHtml(d);
        tip.style.display = 'block';
        const r = view.getBoundingClientRect();
        let x = ev.clientX - r.left + 14, y = ev.clientY - r.top + 14;
        if (x + tip.offsetWidth > r.width - 8) x = ev.clientX - r.left - tip.offsetWidth - 14;
        if (y + tip.offsetHeight > r.height - 8) y = ev.clientY - r.top - tip.offsetHeight - 14;
        tip.style.left = x + 'px'; tip.style.top = y + 'px';
      };
      renderer.domElement.addEventListener('pointermove', onMove);
      renderer.domElement.addEventListener('pointerleave', () => { tip.style.display = 'none'; });
      renderer.domElement.addEventListener('pointerdown', (ev) => { downAt = [ev.clientX, ev.clientY]; });
      renderer.domElement.addEventListener('pointerup', (ev) => {
        if (!downAt || Math.hypot(ev.clientX - downAt[0], ev.clientY - downAt[1]) > 4) return;
        const d = pick(ev);
        if (d) kit.select(d.id);
        else if (selected) { selected = null; paint(); } // clear locally; don't send null to other pages
      });

      // ---------- selection & search ----------
      kit.onSelect((id) => { selected = id; paint(); });
      kit.onSearch((q) => {
        const s = q.toLowerCase();
        if (info.has(q) || spinePos.has(q)) return; // exact names go through onSelect
        const ids = new Set(racks.filter((r) => r.id.toLowerCase().includes(s) || kit.siteName(r.site).toLowerCase() === s).map((r) => r.id));
        setFocus(ids.size ? { key: '?' + q, label: `Search "${q}"`, ids } : null);
      });

      cleanup = () => {
        ro.disconnect();
        window.removeEventListener('keydown', onKey);
        controls.dispose();
        for (const c of lineGroup.children) { c.geometry.dispose(); c.material.dispose(); }
        for (const d of disposables) d.dispose && d.dispose();
        bodies.dispose(); caps.dispose(); spineMesh.dispose();
        renderer.dispose();
        cleanup = null;
      };

      drawLegend();
      drawTable();
      paint();
      size();
    }
  };
});
