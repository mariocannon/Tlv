# Verity landing page (Astro)

Pilot landing page served at https://mariocannon.github.io/Tlv/

    cd site
    npm install
    npm run dev      # local preview at http://localhost:4321/Tlv/
    npm run pages    # build and copy into ../docs (GitHub Pages), then commit and push

`npm run pages` only replaces `docs/index.html` and `docs/_astro/`; the tap page (`docs/t/`),
dashboard (`docs/dashboard/`) and `docs/config.js` are left alone.
The pilot form writes to the Supabase table `pilot_leads` (insert-only for visitors);
applications show up on the staff dashboard.
