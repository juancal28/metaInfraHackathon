      // Backbone page: each site is a plate on a ring with its backbone routers standing on it;
      // backbone circuits (links between backbone routers at different sites) arc between the plates.
      const bbrs = kit.devicesByTier('backbone_router');
      const ids = new Set(bbrs.map((d) => d.id));
      const isCircuit = (l) => ids.has(l.a) && ids.has(l.b) && kit.device(l.a).site !== kit.device(l.b).site;
      const circuits = model.links.filter(isCircuit);
      const sites = model.sites.filter((s) => bbrs.some((d) => d.site === s.code));
      const n = sites.length;
      const maxPer = d3.max(sites, (s) => bbrs.filter((d) => d.site === s.code).length) || 1;
      const plateW = Math.max(6, maxPer * 2.4 + 1.6), plateD = 4.4;
      const ring = n <= 1 ? 0 : Math.max(9, (n * (plateW + 5)) / (2 * Math.PI));
      const nodes = [], plates = [], labels = [];
      const center = new Map();
      sites.forEach((s, i) => {
        const a = n <= 1 ? 0 : (i / n) * Math.PI * 2 - Math.PI / 2;
        const cx = Math.cos(a) * ring, cz = Math.sin(a) * ring;
        center.set(s.code, [cx, cz]);
        plates.push({ x: cx, z: cz, w: plateW, d: plateD, t: 0.35 });
        // site name sits on the outer side of the plate
        const out = n <= 1 ? [0, 1] : [Math.cos(a), Math.sin(a)];
        const nameW = s.name.length * 0.95;
        const off = Math.abs(out[0]) * (plateW / 2 + nameW / 2 + 0.8) + Math.abs(out[1]) * (plateD / 2 + 1.4);
        labels.push({ text: s.name, p: [cx + out[0] * off, 0.03, cz + out[1] * off], h: 1.6, flat: true });
        labels.push({ text: s.code, p: [cx, 0.03, cz + plateD / 2 - 0.6], h: 0.6, color: '#8c959f', flat: true, weight: 600 });
        const mine = bbrs.filter((d) => d.site === s.code).sort((p, q) => d3.ascending(p.id, q.id));
        mine.forEach((d, k) => {
          const p = [rowX(k, mine.length, cx, 2.4, plateW - 1.6), 1.1, cz];
          nodes.push({ id: d.id, p, s: [1.4, 2.2, 1.4] });
          labels.push({ text: d.id.replace(d.site + '-', ''), p: [p[0], 2.9, cz], h: 0.6, color: '#3b4656', weight: 600 });
        });
      });
      const pairKey = (l) => [kit.device(l.a).site, kit.device(l.b).site].sort().join('|');
      return {
        nodes, plates, labels, links: circuits, arc: (l, a, b) => 1.5 + a.distanceTo(b) * 0.28,
        tube: 0.16, okTubes: true, elev: 0.95, deviceWord: 'Backbone routers', linkWord: 'Backbone circuits',
        groupings: [
          { name: 'Circuit', title: 'Circuit', cols: ['bad', 'broken', 'partial', 'down'],
            groups: () => circuits.map((l, i) => ({
              key: 'c' + i, label: `${l.a} ↔ ${l.b}`, find: kit.siteName(kit.device(l.a).site) + ' ' + kit.siteName(kit.device(l.b).site),
              sk: [pairKey(l), l.a, l.b], nodes: new Set([l.a, l.b]), links: [l] })) },
          { name: 'Site pair', title: 'Between sites', cols: ['links', 'bad', 'broken', 'partial', 'down'],
            groups: () => d3.groups(circuits, pairKey).map(([k, ls]) => {
              const [a, b] = k.split('|');
              return { key: k, label: `${kit.siteName(a)} ↔ ${kit.siteName(b)}`, sk: [k], links: ls,
                nodes: new Set(ls.flatMap((l) => [l.a, l.b])) };
            }) },
          { name: 'Router', title: 'Backbone router', cols: ['links', 'bad', 'broken', 'partial', 'drained', 'down'],
            groups: () => bbrs.map((d) => deviceGroup(kit, d, circuits.filter((l) => l.a === d.id || l.b === d.id))) },
          { name: 'Site', title: 'Site',
            groups: () => sites.map((s) => {
              const ns = new Set(bbrs.filter((d) => d.site === s.code).map((d) => d.id));
              return { key: s.code, label: s.name, sk: [s.code], nodes: ns, links: circuits.filter((l) => ns.has(l.a) || ns.has(l.b)) };
            }) },
        ],
      };
