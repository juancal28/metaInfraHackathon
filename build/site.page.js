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
