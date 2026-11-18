#!/usr/bin/env python3
"""Writes panels/<page>.js for each page: the shared engine plus that page's layout, all inside kit.page(...)."""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.join(HERE, '..', 'panels')
TITLES = {
    'overview': 'Overview page: the whole network, every site as a tower of tiers, with the backbone circuits arcing between sites.',
    'backbone': 'Backbone page: sites around a ring, their backbone routers, and the backbone circuits between sites.',
    'site': 'Site page: super-spines by plane, border routers and backbone routers for each site, and the links between them.',
    'pods': 'Pods page: each pod\'s spines and their uplinks to the super-spines.',
}

engine = open(os.path.join(HERE, 'engine.js')).read()
pages = sys.argv[1:] or [p for p in TITLES if os.path.exists(os.path.join(HERE, p + '.page.js'))]
for page in pages:
    body = open(os.path.join(HERE, page + '.page.js')).read()
    out = f"""// {TITLES[page]}
// 3D (drag to rotate), every device on screen at open, broken / partly broken links and drained devices each look
// different (legend at the bottom), and a sortable, filterable table to find answers fast.
// Everything is drawn from the loaded topology; nothing about counts or sizes is hard-coded.
// All code, helpers too, lives inside kit.page(...) so it cannot clash with other pages.

kit.page('{page}', function () {{
  let current = null;

{engine}
  function layout(el, model, kit) {{
{body}  }}

  return {{
    resize() {{ if (current) current.resize(); }},
    mount(el, model, kit) {{
      if (current) current.cleanup();
      current = engine(el, model, kit, layout(el, model, kit));
    }},
  }};
}});
"""
    open(os.path.join(KIT, page + '.js'), 'w').write(out)
    print('wrote', page)
