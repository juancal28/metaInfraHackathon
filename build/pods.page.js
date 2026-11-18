      // Pods page: per site, each pod is a plate with its spines (one row per plane);
      // the site's super-spines float above, one row per plane, so each spine's uplinks fan up to its plane.
      const spines = kit.devicesByTier('spine');
      const supers = kit.devicesByTier('super_spine');
      const scope = (l) => {
        const ta = kit.device(l.a).tier, tb = kit.device(l.b).tier;
        return (ta === 'spine' && tb === 'super_spine') || (ta === 'super_spine' && tb === 'spine');
      };
      const scoped = model.links.filter(scope);
      const sites = model.sites.filter((s) => spines.some((d) => d.site === s.code) || supers.some((d) => d.site === s.code));
      const SS_Y = 9, POD_PITCH = 3.2;
      const aspect = (el.clientWidth || window.innerWidth - 480) / (el.clientHeight || window.innerHeight - 60);
      const blocks = sites.map((s) => {
        const sp = spines.filter((d) => d.site === s.code), ss = supers.filter((d) => d.site === s.code);
        const pods = uniq(sp.map((d) => d.pod)).sort(byNum);
        const planes = uniq([...sp, ...ss].map((d) => d.plane)).sort(byNum);
        const perPodPlane = d3.max(pods.flatMap((p) => planes.map((pl) => sp.filter((d) => d.pod === p && d.plane === pl).length))) || 1;
        const podW = Math.max(2.2, perPodPlane * 1.2 + 0.6);
        const pitch = Math.max(POD_PITCH, podW + 0.8);
        const w = Math.max(pods.length * pitch, 8);
        const d = planes.length * 2.4 + 2;
        return { s, sp, ss, pods, planes, podW, pitch, w, d, h: SS_Y + 2 };
      });
      arrangeBlocks(blocks, aspect, 6, SS_Y + 4);
      const nodes = [], plates = [], labels = [];
      for (const b of blocks) {
        const cx = b.ox + b.w / 2, cz = b.oz + b.d / 2;
        const planeZ = (pl) => cz + (b.planes.indexOf(pl) - (b.planes.length - 1) / 2) * 2.4;
        b.pods.forEach((p, i) => {
          const x = b.ox + (i + 0.5) * b.pitch;
          plates.push({ x, z: cz, w: b.podW, d: b.planes.length * 2.4 - 0.6 });
          labels.push({ text: 'Pod ' + p, p: [x, 0.02, cz + (b.planes.length * 2.4) / 2 + 0.25], h: 0.7, color: '#2f6feb', flat: true });
          for (const pl of b.planes) {
            const row = b.sp.filter((d) => d.pod === p && d.plane === pl).sort((a, c) => d3.ascending(a.id, c.id));
            row.forEach((d, k) => nodes.push({ id: d.id, p: [rowX(k, row.length, x, 1.2, b.podW - 0.6), 0.35, planeZ(pl)], s: [0.9, 0.7, 0.8] }));
          }
          // spines without a plane still need a home
          const loose = b.sp.filter((d) => d.pod === p && !b.planes.includes(d.plane));
          loose.forEach((d, k) => nodes.push({ id: d.id, p: [rowX(k, loose.length, x, 1.2, b.podW), 0.35, cz], s: [0.9, 0.7, 0.8] }));
        });
        for (const pl of b.planes) {
          const row = b.ss.filter((d) => d.plane === pl).sort((a, c) => d3.ascending(a.id, c.id));
          row.forEach((d, k) => nodes.push({ id: d.id, p: [rowX(k, row.length, cx, 2.2, b.w - 2), SS_Y, planeZ(pl)], s: [1.1, 0.8, 0.9] }));
          if (row.length) labels.push({ text: pl == null ? 'Super-spines' : 'Plane ' + pl, p: [b.ox - 1.6, SS_Y, planeZ(pl)], h: 0.6, color: '#3b4656', weight: 600 });
        }
        labels.push({ text: b.s.name, p: [cx, SS_Y + 2.2, b.oz - 0.5], h: 1.5 });
      }
      return {
        nodes, plates, labels, links: scoped, deviceWord: 'Spines & super-spines', linkWord: 'Spine uplinks', elev: 0.75, tube: 0.07,
        groupings: [
          { name: 'Spine', title: 'Spine', kind: 'device',
            groups: () => spines.map((d) => deviceGroup(kit, d, kit.linksOf(d.id))) },
          { name: 'Pod', title: 'Pod',
            groups: () => d3.groups(spines, (d) => d.site + '|' + d.pod).map(([k, ds]) => {
              const ids = new Set(ds.map((d) => d.id));
              return { key: k, label: `${kit.siteName(ds[0].site)} · Pod ${ds[0].pod}`, sk: [ds[0].site, ds[0].pod ?? -1], nodes: ids, links: scoped.filter((l) => ids.has(l.a) || ids.has(l.b)) };
            }) },
          { name: 'Super-spine', title: 'Super-spine', kind: 'device',
            groups: () => supers.map((d) => deviceGroup(kit, d, kit.linksOf(d.id))) },
          { name: 'Site', title: 'Site',
            groups: () => sites.map((s) => {
              const ids = new Set([...spines, ...supers].filter((d) => d.site === s.code).map((d) => d.id));
              return { key: s.code, label: s.name, sk: [s.code], nodes: ids, links: scoped.filter((l) => ids.has(l.a) || ids.has(l.b)) };
            }) },
        ],
      };
