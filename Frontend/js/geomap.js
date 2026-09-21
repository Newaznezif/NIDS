/* Investigation Geography map.
   Renders a country choropleth + IP markers from /api/wb/map. Only artifacts
   the backend actually geolocated appear here; nothing is fabricated. Colour
   intensity = INVESTIGATION ACTIVITY, never maliciousness (see legend text).
   Dependency-free: hand-rolled equirectangular projection, bundled GeoJSON. */
(function () {
  const W = 1000, H = 500;
  const GEO_URL = "/assets/world-countries.geo.json";

  /* ISO 3166-1 alpha-2 -> alpha-3 (backend stores alpha-2 from ipwho.is). */
  const A2A3 = ("AD AND,AE ARE,AF AFG,AG ATG,AI AIA,AL ALB,AM ARM,AO AGO,AQ ATA,AR ARG,AS ASM,AT AUT,AU AUS,AW ABW,AX ALA,AZ AZE,BA BIH,BB BRB,BD BGD,BE BEL,BF BFA,BG BGR,BH BHR,BI BDI,BJ BEN,BL BLM,BM BMU,BN BRN,BO BOL,BQ BES,BR BRA,BS BHS,BT BTN,BV BVT,BW BWA,BY BLR,BZ BLZ,CA CAN,CC CCK,CD COD,CF CAF,CG COG,CH CHE,CI CIV,CK COK,CL CHL,CM CMR,CN CHN,CO COL,CR CRI,CU CUB,CV CPV,CW CUW,CX CXR,CY CYP,CZ CZE,DE DEU,DJ DJI,DK DNK,DM DMA,DO DOM,DZ DZA,EC ECU,EE EST,EG EGY,EH ESH,ER ERI,ES ESP,ET ETH,FI FIN,FJ FJI,FK FLK,FM FSM,FO FRO,FR FRA,GA GAB,GB GBR,GD GRD,GE GEO,GF GUF,GG GGY,GH GHA,GI GIB,GL GRL,GM GMB,GN GIN,GP GLP,GQ GNQ,GR GRC,GS SGS,GT GTM,GU GUM,GW GNB,GY GUY,HK HKG,HM HMD,HN HND,HR HRV,HT HTI,HU HUN,ID IDN,IE IRL,IL ISR,IM IMN,IN IND,IO IOT,IQ IRQ,IR IRN,IS ISL,IT ITA,JE JEY,JM JAM,JO JOR,JP JPN,KE KEN,KG KGZ,KH KHM,KI KIR,KM COM,KN KNA,KP PRK,KR KOR,KW KWT,KY CYM,KZ KAZ,LA LAO,LB LBN,LC LCA,LI LIE,LK LKA,LR LBR,LS LSO,LT LTU,LU LUX,LV LVA,LY LBY,MA MAR,MC MCO,MD MDA,ME MNE,MF MAF,MG MDG,MH MHL,MK MKD,ML MLI,MM MMR,MN MNG,MO MAC,MP MNP,MQ MTQ,MR MRT,MS MSR,MT MLT,MU MUS,MV MDV,MW MWI,MX MEX,MY MYS,MZ MOZ,NA NAM,NC NCL,NE NER,NF NFK,NG NGA,NI NIC,NL NLD,NO NOR,NP NPL,NR NRU,NU NIU,NZ NZL,OM OMN,PA PAN,PE PER,PF PYF,PG PNG,PH PHL,PK PAK,PL POL,PM SPM,PN PCN,PR PRI,PS PSE,PT PRT,PW PLW,PY PRY,QA QAT,RE REU,RO ROU,RS SRB,RU RUS,RW RWA,SA SAU,SB SLB,SC SYC,SD SDN,SE SWE,SG SGP,SH SHN,SI SVN,SJ SJM,SK SVK,SL SLE,SM SMR,SN SEN,SO SOM,SR SUR,SS SSD,ST STP,SV SLV,SX SXM,SY SYR,SZ SWZ,TC TCA,TD TCD,TF ATF,TG TGO,TH THA,TJ TJK,TK TKL,TL TLS,TM TKM,TN TUN,TO TON,TR TUR,TT TTO,TV TUV,TW TWN,TZ TZA,UA UKR,UG UGA,UM UMI,US USA,UY URY,UZ UZB,VA VAT,VC VCT,VE VEN,VG VGB,VI VIR,VN VNM,VU VUT,WF WLF,WS WSM,YE YEM,YT MYT,ZA ZAF,ZM ZMB,ZW ZWE")
    .split(",").reduce((m, p) => { const [a, b] = p.split(" "); m[a] = b; return m; }, {});

  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  const px = (lon) => ((lon + 180) / 360) * W;
  const py = (lat) => ((90 - lat) / 180) * H;

  function ringPath(ring) {
    let d = "", prevLon = null;
    for (const [lon, lat] of ring) {
      const X = px(lon).toFixed(1), Y = py(lat).toFixed(1);
      // Break the line across the antimeridian to avoid wrap-around streaks.
      if (prevLon !== null && Math.abs(lon - prevLon) > 180) d += `M${X} ${Y}`;
      else d += (d ? "L" : "M") + X + " " + Y;
      prevLon = lon;
    }
    return d + "Z";
  }
  function featurePath(feature) {
    const g = feature.geometry;
    if (!g) return "";
    if (g.type === "Polygon") return g.coordinates.map(ringPath).join("");
    if (g.type === "MultiPolygon") return g.coordinates.map((p) => p.map(ringPath).join("")).join("");
    return "";
  }

  function markerRadius(count, maxCount) {
    if (!maxCount) return 3;
    return 2.5 + 5 * Math.sqrt(count / maxCount);
  }

  async function render(container, opts) {
    opts = opts || {};
    container.innerHTML = '<div class="geo-empty">Loading investigation geography…</div>';
    let payload, geo;
    try {
      const [mapRes, geoRes] = await Promise.all([
        fetch("/api/wb/map", { headers: { Accept: "application/json" } }).then((r) => r.json()),
        fetch(GEO_URL).then((r) => (r.ok ? r.json() : null)),
      ]);
      payload = mapRes; geo = geoRes;
    } catch (e) {
      container.innerHTML = '<div class="geo-empty">Could not load map data.</div>';
      return;
    }
    if (!payload || !Array.isArray(payload.countries)) {
      container.innerHTML = '<div class="geo-empty">No map data available.</div>';
      return;
    }

    const countries = payload.countries, markers = payload.markers || [];
    const totals = payload.totals || {}, legend = payload.legend || { levels: [] };

    // activity lookup by alpha-3 and by country name (fallback)
    const byA3 = {}, byName = {};
    countries.forEach((c) => {
      if (c.country_code && A2A3[c.country_code.toUpperCase()]) byA3[A2A3[c.country_code.toUpperCase()]] = c;
      if (c.country) byName[c.country.toLowerCase()] = c;
    });

    let head = `<div class="geo-head"><div><h2>Investigation Geography</h2>
      <div class="sub">Geographic distribution of artifacts that returned real geolocation.
      ${esc(payload.provenance || "EXTERNAL INTELLIGENCE")}</div></div></div>`;

    // Legend (activity, explicitly NOT maliciousness)
    let legendHtml = '<div class="geo-legend"><span>Investigation activity:</span>';
    (legend.levels || []).forEach((l) => {
      legendHtml += `<span class="swatch"><i style="background:${esc(l.color)}"></i>${esc(l.label)}</span>`;
    });
    legendHtml += '<span class="swatch"><i style="background:#1e293b;border:1px solid rgba(255,255,255,.15)"></i>No recorded activity</span></div>';
    const note = `<div class="geo-note">${esc(legend.meaning || "")}</div>`;

    let body;
    if (!geo) {
      // Offline / base map unavailable: stay honest, list real data instead.
      body = '<div class="geo-empty">Map base layer unavailable (offline). ' +
        'Geolocated artifacts are listed below.</div>';
    } else {
      let paths = "";
      geo.features.forEach((f) => {
        const d = featurePath(f);
        if (!d) return;
        const act = byA3[f.id] || byName[(f.properties && f.properties.name || "").toLowerCase()];
        const fill = act ? act.activity_color : "";
        const cls = "geo-country" + (act ? " has-activity" : "");
        const dataName = esc(f.properties && f.properties.name || f.id);
        paths += `<path class="${cls}" d="${d}" ${fill ? `fill="${fill}"` : ""} data-name="${dataName}"></path>`;
      });
      const maxMarker = markers.reduce((m, x) => Math.max(m, x.investigation_count || 0), 0);
      let dots = "";
      markers.forEach((m) => {
        if (m.latitude == null || m.longitude == null) return;
        const r = markerRadius(m.investigation_count || 1, maxMarker).toFixed(1);
        dots += `<circle class="geo-marker" cx="${px(m.longitude).toFixed(1)}" cy="${py(m.latitude).toFixed(1)}" r="${r}" fill="${esc(m.activity_color || "#00f2fe")}" data-ip="${esc(m.artifact)}"></circle>`;
      });
      body = `<div class="geo-map-wrap"><svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Investigation geography map"><g>${paths}</g><g>${dots}</g></svg><div class="geo-tooltip" id="geo-tt"></div></div>`;
    }

    const side = `<div class="geo-side">
      <div class="stat"><b>${totals.countries || 0}</b> countries</div>
      <div class="stat"><b>${totals.unique_artifacts || 0}</b> unique geolocated artifacts</div>
      <div class="stat"><b>${totals.investigations || 0}</b> investigations with geolocation</div>
      <div class="stat" id="geo-detail" style="flex:1;min-width:240px"></div>
    </div>`;

    container.innerHTML = head + legendHtml + note + body + side;

    // ---- interactivity ----
    const tt = container.querySelector("#geo-tt");
    const wrap = container.querySelector(".geo-map-wrap");
    const detail = container.querySelector("#geo-detail");

    function showTip(html, evt) {
      if (!tt) return;
      tt.innerHTML = html; tt.classList.add("open");
      const rect = wrap.getBoundingClientRect();
      let x = evt.clientX - rect.left + 12, y = evt.clientY - rect.top + 12;
      if (x + 240 > rect.width) x = evt.clientX - rect.left - 250;
      tt.style.left = x + "px"; tt.style.top = y + "px";
    }
    const hideTip = () => { if (tt) tt.classList.remove("open"); };

    const countryByFeatureName = {};
    countries.forEach((c) => { countryByFeatureName[(c.country || "").toLowerCase()] = c; });

    container.querySelectorAll(".geo-country").forEach((p) => {
      p.addEventListener("mousemove", (e) => {
        const name = (p.getAttribute("data-name") || "").toLowerCase();
        const act = countryByFeatureName[name];
        if (!act) { hideTip(); return; }
        showTip(`<div class="tt-title">${esc(act.country || p.getAttribute("data-name"))}</div>
          <div class="tt-row">Investigations: <b>${act.investigations}</b></div>
          <div class="tt-row">Unique IPs: <b>${act.unique_ips}</b></div>
          <div class="tt-row">Last investigated: <b>${esc(fmt(act.last_investigated))}</b></div>
          <div class="tt-row">Activity: <b>${esc((act.activity_level || "").replace("_", " "))}</b></div>`, e);
      });
      p.addEventListener("mouseleave", hideTip);
    });

    container.querySelectorAll(".geo-marker").forEach((c) => {
      const ip = c.getAttribute("data-ip");
      const m = markers.find((x) => x.artifact === ip) || {};
      c.addEventListener("mousemove", (e) => {
        showTip(`<div class="tt-title">${esc(ip)}</div>
          <div class="tt-row">${esc([m.city, m.country].filter(Boolean).join(", ") || "Location unavailable")}</div>
          <div class="tt-row">Investigations: <b>${m.investigation_count || 0}</b></div>`, e);
      });
      c.addEventListener("mouseleave", hideTip);
      c.addEventListener("click", () => {
        detail.innerHTML = `<div class="tt-title">${esc(ip)}</div>
          <div class="tt-row">Country: <b>${esc(m.country || "Unavailable")}</b></div>
          <div class="tt-row">City: <b>${esc(m.city || "Unavailable")}</b></div>
          <div class="tt-row">ASN: <b>${esc(m.asn || "Unavailable")}</b></div>
          <div class="tt-row">Organization: <b>${esc(m.organization || "Unavailable")}</b></div>
          <div class="tt-row">Provider: <b>${esc(m.geo_provider || "Unavailable")}</b></div>
          <div class="tt-row">Investigations: <b>${m.investigation_count || 0}</b></div>
          <div class="tt-row">First seen: <b>${esc(fmt(m.first_seen))}</b></div>
          <div class="tt-row">Last seen: <b>${esc(fmt(m.last_seen))}</b></div>
          <button class="geo-investigate-btn" data-ip="${esc(ip)}">Investigate IP</button>`;
        const btn = detail.querySelector(".geo-investigate-btn");
        if (btn && typeof opts.onInvestigate === "function") {
          btn.onclick = () => opts.onInvestigate(ip);
        }
      });
    });
  }

  function fmt(ts) {
    if (!ts) return "Unavailable";
    const s = String(ts);
    return s.length >= 19 ? s.slice(0, 19).replace("T", " ") + " UTC" : s;
  }

  window.NIDSGeoMap = { render };
})();
