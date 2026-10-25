// Runs before the first paint, as a classic script so that it also runs where
// the module app cannot: opened from disk (file://, where browsers refuse to
// load modules or read the data files) or in a browser without modules.
//
// When the app can run, it marks <html class="js"> so the live sections show
// instead of the static fallback links. If the app has not started after a
// while (a failed load, a blocked script), the fallback comes back.
(function () {
  'use strict';
  var root = document.documentElement;
  var fromDisk = location.protocol === 'file:';
  var modules = 'noModule' in HTMLScriptElement.prototype;

  function fail(reason) {
    root.classList.remove('js');
    var show = function () {
      document.getElementById('boot-reason').textContent = reason;
      document.getElementById('boot-failed').hidden = false;
    };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', show);
    else show();
  }

  if (fromDisk) {
    fail('Browsers do not let a page opened from disk read its data files. ' +
      'Serve the folder instead: run "python3 -m http.server" in it and open http://localhost:8000/.');
    return;
  }
  if (!modules) {
    fail('This browser does not support JavaScript modules.');
    return;
  }
  root.classList.add('js');
  setTimeout(function () {
    if (root.dataset.app !== 'started') fail('The script did not load. Reloading the page may help.');
  }, 10000);
})();
