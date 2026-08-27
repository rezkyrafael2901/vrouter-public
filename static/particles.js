/* ═══════════════════════════════════════════════════════════════
   VROUTER PARTICLE NETWORK — shared canvas background
   Dark mode only. Zero overhead in light mode.
   ═══════════════════════════════════════════════════════════════ */
(function () {
  if (typeof window === 'undefined') return;
  var isDark = document.documentElement.classList.contains('dark');
  if (!isDark) return;

  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  var canvas = document.createElement('canvas');
  canvas.id = 'particle-network';
  document.body.prepend(canvas);

  var ctx = canvas.getContext('2d');
  var particles = [];
  var mouse = { x: -9999, y: -9999 };
  var animId = null;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  var count = Math.min(70, Math.floor(canvas.width * canvas.height / 16000));
  var colors = ['rgba(139,92,246,', 'rgba(16,185,129,', 'rgba(99,102,241,'];

  for (var i = 0; i < count; i++) {
    particles.push({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.5,
      vy: (Math.random() - 0.5) * 0.5,
      r: Math.random() * 2 + 1.5,
      c: colors[i % 3],
    });
  }

  document.addEventListener('mousemove', function (e) { mouse.x = e.clientX; mouse.y = e.clientY; });
  document.addEventListener('mouseleave', function () { mouse.x = -9999; mouse.y = -9999; });

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    for (var i = 0; i < particles.length; i++) {
      var p = particles[i];
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
      if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = p.c + '0.5)';
      ctx.fill();

      for (var j = i + 1; j < particles.length; j++) {
        var q = particles[j];
        var dx = p.x - q.x;
        var dy = p.y - q.y;
        var dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 140) {
          var alpha = (1 - dist / 140) * 0.25;
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(q.x, q.y);
          ctx.strokeStyle = p.c + alpha + ')';
          ctx.lineWidth = 0.8;
          ctx.stroke();
        }
      }

      var mx = p.x - mouse.x;
      var my = p.y - mouse.y;
      var md = Math.sqrt(mx * mx + my * my);
      if (md < 180) {
        ctx.beginPath();
        ctx.moveTo(p.x, p.y);
        ctx.lineTo(mouse.x, mouse.y);
        ctx.strokeStyle = 'rgba(139,92,246,' + (1 - md / 180) * 0.15 + ')';
        ctx.lineWidth = 0.6;
        ctx.stroke();
      }
    }

    animId = requestAnimationFrame(draw);
  }
  draw();
})();
