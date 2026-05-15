/* ══════════════════════════════════════════════════════════════
   ARGUS · WebGL spatial-3D background scene
   ──────────────────────────────────────────────────────────────
   Lazy-loaded ONLY when the user picks the "Spatial 3D" skin.
   Mounts a full-bleed Three.js canvas behind the UI showing:
     - A central wire-frame icosahedron representing the target host
     - Orbiting "service satellites" (small octahedra) for each
       discovered port / service
     - Glowing particle trails for findings — particles drift inward
       toward the central host
     - Soft starfield backdrop
     - Subtle camera dolly on phase change

   Uses Three.js via the unpkg ESM CDN. If the network is offline /
   blocked, the skin gracefully degrades to the plain glass overlay
   (the webgl.css panels still look great over a solid #000814).

   API exposed:
     window.__argusWebglScene = { mount(), unmount(), setRiskLevel(0-1) }
   ══════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  if (window.__argusWebglScene) return;  // idempotent

  let scene, camera, renderer, target, satellites = [], particles, raf;
  let mounted = false;
  let riskLevel = 0.4;

  async function loadThree() {
    // Use module-CDN. Fall back gracefully if blocked.
    try {
      const m = await import('https://unpkg.com/three@0.160.0/build/three.module.js');
      return m;
    } catch (e) {
      console.warn('[argus-webgl] Three.js CDN unreachable; skin will use static glass only.', e);
      return null;
    }
  }

  async function mount() {
    if (mounted) return;
    const THREE = await loadThree();
    if (!THREE) return;

    // Container
    let canvas = document.getElementById('argus-webgl-canvas');
    if (!canvas) {
      canvas = document.createElement('canvas');
      canvas.id = 'argus-webgl-canvas';
      document.body.prepend(canvas);
    }

    renderer = new THREE.WebGLRenderer({
      canvas, alpha: true, antialias: true, powerPreference: 'high-performance',
    });
    renderer.setPixelRatio(Math.min(2, window.devicePixelRatio || 1));
    renderer.setSize(window.innerWidth, window.innerHeight);

    scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x000814, 0.018);

    camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 200);
    camera.position.set(0, 1.2, 14);

    // Lighting — rim cyan, fill violet
    scene.add(new THREE.AmbientLight(0x223344, 0.55));
    const rimCyan = new THREE.PointLight(0x00D9FF, 1.4, 80);
    rimCyan.position.set(8, 6, 6);
    scene.add(rimCyan);
    const fillVio = new THREE.PointLight(0x8A4FFF, 1.1, 60);
    fillVio.position.set(-7, -4, 4);
    scene.add(fillVio);

    // Central host — wireframe icosahedron, glowing core
    const hostGeom = new THREE.IcosahedronGeometry(2.6, 1);
    const hostWire = new THREE.LineSegments(
      new THREE.WireframeGeometry(hostGeom),
      new THREE.LineBasicMaterial({ color: 0x00D9FF, transparent: true, opacity: 0.55 })
    );
    const hostCore = new THREE.Mesh(
      new THREE.IcosahedronGeometry(2.4, 1),
      new THREE.MeshBasicMaterial({ color: 0x002B40, transparent: true, opacity: 0.32 })
    );
    target = new THREE.Group();
    target.add(hostWire);
    target.add(hostCore);
    scene.add(target);

    // Orbiting service satellites
    const satCount = 8;
    for (let i = 0; i < satCount; i++) {
      const geo = new THREE.OctahedronGeometry(0.30, 0);
      const mat = new THREE.MeshBasicMaterial({
        color: i % 2 === 0 ? 0x00D9FF : 0xFF6FB5,
        wireframe: true,
        transparent: true, opacity: 0.85,
      });
      const sat = new THREE.Mesh(geo, mat);
      const angle = (i / satCount) * Math.PI * 2;
      const radius = 5.5 + Math.sin(i) * 0.6;
      sat.position.set(Math.cos(angle) * radius, Math.sin(i * 0.7) * 1.6, Math.sin(angle) * radius);
      sat.userData.angle = angle;
      sat.userData.radius = radius;
      sat.userData.speed = 0.10 + (i % 3) * 0.04;
      sat.userData.tilt = (i % 2 === 0) ? 0.3 : -0.4;
      satellites.push(sat);
      scene.add(sat);
    }

    // Particle starfield + finding trails
    const pCount = 1400;
    const pPos = new Float32Array(pCount * 3);
    const pColor = new Float32Array(pCount * 3);
    for (let i = 0; i < pCount; i++) {
      const r = 30 + Math.random() * 90;
      const t = Math.acos(2 * Math.random() - 1);
      const p = Math.random() * Math.PI * 2;
      pPos[i * 3]     = r * Math.sin(t) * Math.cos(p);
      pPos[i * 3 + 1] = r * Math.cos(t);
      pPos[i * 3 + 2] = r * Math.sin(t) * Math.sin(p);
      const c = Math.random();
      if (c < 0.6)      { pColor[i * 3] = 0.5; pColor[i * 3 + 1] = 0.85; pColor[i * 3 + 2] = 1.0; } // cyan
      else if (c < 0.85){ pColor[i * 3] = 1.0; pColor[i * 3 + 1] = 0.4;  pColor[i * 3 + 2] = 0.7; } // magenta
      else              { pColor[i * 3] = 1.0; pColor[i * 3 + 1] = 1.0;  pColor[i * 3 + 2] = 1.0; } // white
    }
    const pGeom = new THREE.BufferGeometry();
    pGeom.setAttribute('position', new THREE.BufferAttribute(pPos, 3));
    pGeom.setAttribute('color',    new THREE.BufferAttribute(pColor, 3));
    particles = new THREE.Points(
      pGeom,
      new THREE.PointsMaterial({
        size: 0.18,
        sizeAttenuation: true,
        vertexColors: true,
        transparent: true,
        opacity: 0.85,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      })
    );
    scene.add(particles);

    function tick(t) {
      raf = requestAnimationFrame(tick);
      const dt = 0.001 * (t || 0);

      // Spin target host
      target.rotation.x = dt * 0.18;
      target.rotation.y = dt * 0.32;

      // Wobble core scale with risk level
      const pulse = 1 + 0.04 * Math.sin(dt * 1.4) * (1 + riskLevel * 1.6);
      target.scale.setScalar(pulse);

      // Animate satellites
      satellites.forEach((s, i) => {
        s.userData.angle += s.userData.speed * 0.008;
        const a = s.userData.angle;
        const r = s.userData.radius;
        s.position.set(
          Math.cos(a) * r,
          Math.sin(dt * 0.4 + i) * 1.4 + s.userData.tilt,
          Math.sin(a) * r,
        );
        s.rotation.x += 0.01; s.rotation.y += 0.015;
      });

      // Slow starfield rotation
      particles.rotation.y = dt * 0.012;

      // Subtle camera dolly
      camera.position.x = Math.sin(dt * 0.08) * 1.4;
      camera.position.y = 1.2 + Math.sin(dt * 0.06) * 0.4;
      camera.lookAt(0, 0, 0);

      renderer.render(scene, camera);
    }
    raf = requestAnimationFrame(tick);

    function onResize() {
      if (!renderer) return;
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    }
    window.addEventListener('resize', onResize);

    mounted = true;
  }

  function unmount() {
    if (!mounted) return;
    cancelAnimationFrame(raf);
    if (renderer) {
      renderer.dispose();
      try { renderer.forceContextLoss(); } catch (_) {}
    }
    const canvas = document.getElementById('argus-webgl-canvas');
    if (canvas) canvas.remove();
    satellites = [];
    scene = camera = renderer = target = particles = null;
    mounted = false;
  }

  function setRiskLevel(v) {
    riskLevel = Math.max(0, Math.min(1, +v || 0));
  }

  window.__argusWebglScene = { mount, unmount, setRiskLevel };

  // Auto-mount on script load (the loader appended us only after the
  // user selected webgl)
  mount();
})();
