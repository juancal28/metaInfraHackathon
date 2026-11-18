      // Overview page: every site is a tower of tiers (racks on the floor at their row/col, then spines,
      // super-spines, border routers and backbone routers stacked above), with backbone circuits arcing between towers.
      const RANK = window.MapCore.TIER_RANK;
      const LEVEL = { top_of_rack: 0.2, spine: 5.5, super_spine: 9.5, border: 13, backbone_router: 16 };
      const RX = 0.62, RZ = 0.82;
      const devs = model.devices;
      const sites = model.sites.filter((s) => devs.some((d) => d.site === s.code));
      const aspect = (el.clientWidth || window.innerWidth - 480) / (el.clientHeight || window.innerHeight - 60);
      const blocks = sites.map((s) => {
        const mine = devs.filter((d) => d.site === s.code);
        const by = (t) => mine.filter((d) => d.tier === t).sort((a, b) => byNum(a.pod, b.pod) || byNum(a.plane, b.plane) || d3.ascending(a.id, b.id));
        const racks = by('top_of_rack');
        const placed = racks.filter((d) => d.row != null && d.col != null);
        const minR = d3.min(placed, (d) => d.row) ?? 1, maxR = d3.max(placed, (d) => d.row) ?? 0;
        const minC = d3.min(placed, (d) => d.col) ?? 1, maxC = d3.max(placed, (d) => d.col) ?? 0;
        const nCol = Math.max(maxC - minC + 1, 0), nRow = Math.max(maxR - minR + 1, 0);
        const spines = by('spine'), sss = by('super_spine');
        const pods = uniq(spines.map((d) => d.pod)).sort(byNum);
        const ssPlanes = uniq(sss.map((d) => d.plane)).sort(byNum);
        const ssPer = d3.max(ssPlanes, (pl) => sss.filter((d) => d.plane === pl).length) || 1;
        const w = Math.max(nCol * RX, pods.length * 1.3, ssPer * 1.4, 6);
        const loose = racks.length - placed.length;
        const extraRows = loose ? Math.ceil(loose / Math.max(nCol, 8)) : 0;
        const d = Math.max((nRow + extraRows) * RZ, 4);
        return { s, mine, by, racks, placed, minR, maxR, minC, maxC, nCol, nRow, spines, sss, pods, ssPlanes, w, d, h: LEVEL.backbone_router + 3 };
      });
      arrangeBlocks(blocks, aspect, 7, 22);
      const nodes = [], plates = [], labels = [], empties = [];
      for (const b of blocks) {
        const cx = b.ox + b.w / 2, cz = b.oz + b.d / 2;
        const x0 = cx - (b.nCol * RX) / 2, z0 = b.oz;
        plates.push({ x: cx, z: cz, w: b.w + 1.2, d: b.d + 1.2 });
        const occ = new Set();
        for (const r of b.placed) {
          occ.add(r.row + ',' + r.col);
          nodes.push({ id: r.id, p: [x0 + (r.col - b.minC + 0.5) * RX, 0.2, z0 + (r.row - b.minR + 0.5) * RZ], s: [0.46, 0.4, 0.6] });
        }
        for (let row = b.minR; row <= b.maxR; row++) for (let c = b.minC; c <= b.maxC; c++)
          if (!occ.has(row + ',' + c)) empties.push({ p: [x0 + (c - b.minC + 0.5) * RX, 0, z0 + (row - b.minR + 0.5) * RZ], w: 0.46, d: 0.6 });
        b.racks.filter((r) => r.row == null || r.col == null).forEach((r, i) => {
          const per = Math.max(b.nCol, 8);
          nodes.push({ id: r.id, p: [x0 + ((i % per) + 0.5) * RX, 0.2, z0 + (b.nRow + Math.floor(i / per) + 0.5) * RZ], s: [0.46, 0.4, 0.6] });
        });
        // spines: one column per pod, one row per plane
        const spPlanes = uniq(b.spines.map((d) => d.plane)).sort(byNum);
        b.pods.forEach((p, i) => {
          const x = rowX(i, b.pods.length, cx, 1.3, b.w);
          const mine = b.spines.filter((d) => d.pod === p);
          mine.forEach((d, k) => {
            const pi = spPlanes.indexOf(d.plane);
            const same = mine.filter((e) => e.plane === d.plane), si = same.indexOf(d);
            nodes.push({ id: d.id, p: [x + (si - (same.length - 1) / 2) * 0.5, LEVEL.spine, cz + (pi - (spPlanes.length - 1) / 2) * 1.6], s: [same.length > 1 ? 0.45 : 0.9, 0.6, 0.8] });
          });
        });
        b.ssPlanes.forEach((pl, pi) => {
          const row = b.sss.filter((d) => d.plane === pl);
          row.forEach((d, k) => nodes.push({ id: d.id, p: [rowX(k, row.length, cx, 1.4, b.w), LEVEL.super_spine, cz + (pi - (b.ssPlanes.length - 1) / 2) * 1.8], s: [1.0, 0.7, 0.9] }));
        });
        for (const t of ['border', 'backbone_router']) {
          const row = b.by(t);
          row.forEach((d, k) => nodes.push({ id: d.id, p: [rowX(k, row.length, cx, 3, b.w), LEVEL[t], cz], s: t === 'border' ? [1.4, 0.8, 1.1] : [1.6, 1.0, 1.3] }));
        }
        labels.push({ text: b.s.name, p: [cx, LEVEL.backbone_router + 2.6, cz], h: 1.6 });
        const lx = b.ox - 1.6;
        labels.push({ text: 'Racks', p: [lx, 0.6, cz], h: 0.55, color: '#5b6573', weight: 600 });
        for (const t of ['spine', 'super_spine', 'border', 'backbone_router'])
          if (b.by(t).length) labels.push({ text: TIER_NAME[t], p: [lx, LEVEL[t], cz], h: 0.55, color: '#5b6573', weight: 600 });
      }
      const crossSite = (l) => kit.device(l.a).site !== kit.device(l.b).site;
      const lowTier = (l) => { const a = kit.device(l.a).tier, b = kit.device(l.b).tier; return RANK[a] <= RANK[b] ? a : b; };
      const tiers = uniq(devs.map((d) => d.tier)).sort((a, b) => RANK[a] - RANK[b]);
      const SHORT = { top_of_rack: 'Racks', spine: 'Spines', super_spine: 'Super-spines', border: 'Borders', backbone_router: 'Backbone rtrs' };
      const tierLabel = (t) => { const i = tiers.indexOf(t); return i < tiers.length - 1 ? `${SHORT[t] || t} → ${SHORT[tiers[i + 1]] || tiers[i + 1]}` : 'Backbone circuits'; };
      return {
        nodes, plates, labels, empties, links: model.links, tube: 0.07, elev: 0.5,
        arc: (l, a, b) => (crossSite(l) ? 3 + a.distanceTo(b) * 0.18 : 0),
        deviceWord: 'Devices', linkWord: 'Links',
        groupings: [
          { name: 'Site', title: 'Site (cross-site links in both)',
            groups: () => sites.map((s) => {
              const ns = new Set(devs.filter((d) => d.site === s.code).map((d) => d.id));
              return { key: s.code, label: s.name, sk: [s.code], nodes: ns, links: model.links.filter((l) => ns.has(l.a) || ns.has(l.b)) };
            }) },
          { name: 'Tier', title: 'Link layer',
            groups: () => tiers.map((t) => ({ key: t, label: tierLabel(t), sk: [RANK[t]],
              nodes: new Set(devs.filter((d) => d.tier === t).map((d) => d.id)), links: model.links.filter((l) => lowTier(l) === t) })) },
          { name: 'Site · tier', title: 'Site · link layer',
            groups: () => sites.flatMap((s) => tiers.map((t) => ({ key: s.code + '|' + t, label: `${s.name} · ${tierLabel(t)}`, sk: [s.code, RANK[t]],
              nodes: new Set(devs.filter((d) => d.tier === t && d.site === s.code).map((d) => d.id)),
              links: model.links.filter((l) => lowTier(l) === t && (kit.device(l.a).site === s.code || kit.device(l.b).site === s.code)) }))).filter((g) => g.nodes.size || g.links.length) },
          { name: 'Device', title: 'Device', kind: 'device',
            groups: () => devs.map((d) => deviceGroup(kit, d, kit.linksOf(d.id))) },
        ],
      };
