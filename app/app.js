(function () {
  'use strict';
  var busy = false, current = null, bridges = [], epoch = 0;
  var choices = window.FlowsealStrategies || [], pickerInput = '';
  var actions = ['start', 'stop', 'restart', 'strategy-alt3', 'strategy-alt2', 'autostart-on', 'autostart-off', 'status'];
  choices.forEach(function (choice) { actions.push('strategy-' + choice.id); });
  function el(id) { return document.getElementById(id); }
  function text(id, value) { el(id).textContent = value; }
  function quote(value) { return "'" + value.replace(/'/g, "'\\''") + "'"; }
  function message(value, error) { text('message', value); el('message').className = error ? 'error' : ''; }
  function setEnabled(value) {
    ['start','stop','restart','alt3','alt2','autostart','all-strategies'].forEach(function (id) { el(id).disabled = !value; });
    choices.forEach(function (choice) { el('choice-' + choice.id).disabled = !value; });
    if (value && current) {
      el('start').disabled = current.running;
      el('stop').disabled = !current.running;
      el('restart').disabled = !current.running;
    }
  }
  function render(value) {
    current = value;
    text('status', value.running ? 'Running' : 'Stopped');
    el('status-dot').className = 'dot' + (value.running ? ' running' : '');
    text('status-description', value.running ? 'DPI bypass is active on this TV' : 'Ready to start DPI bypass');
    el('alt3').setAttribute('aria-pressed', value.strategy === 'alt3' ? 'true' : 'false');
    el('alt2').setAttribute('aria-pressed', value.strategy === 'alt2' ? 'true' : 'false');
    var selected = choices.filter(function (choice) { return choice.id === value.strategy; })[0];
    text('current-strategy', 'Current: ' + (value.strategyLabel || (selected && selected.label) || value.strategy));
    choices.forEach(function (choice) { el('choice-' + choice.id).setAttribute('aria-pressed', choice.id === value.strategy ? 'true' : 'false'); });
    el('autostart').setAttribute('aria-checked', value.autostart ? 'true' : 'false');
    text('autostart-label', value.autostart ? 'On' : 'Off');
    text('platform', value.architecture + ' · Linux ' + value.kernel + ' · Homebrew root service');
    var counts = (value.engine && value.engine.counters) || {};
    text('tls-count', counts.transformed || 0);
    text('udp-count', counts.udp_transformed || 0);
    text('fake-count', counts.fake_packets || 0);
    text('limits', (value.limits || []).join(' · '));
    text('log', (value.log || []).join('\n') || 'No service log yet.');
    setEnabled(!busy);
  }
  function call(action, callback) {
    if (actions.indexOf(action) === -1) { callback(new Error('Unknown action')); return; }
    if (typeof PalmServiceBridge === 'undefined') { callback(new Error('Open this app on the rooted LG television.')); return; }
    var path;
    try { path = decodeURIComponent(window.location.pathname).replace(/\/[^/]*$/, ''); }
    catch (error) { callback(error); return; }
    if (!/\/usr\/palm\/applications\/org\.flowseal\.webos$/.test(path)) { callback(new Error('Cannot locate the installed service files.')); return; }
    var bridge = new PalmServiceBridge(), completed = false;
    bridges.push(bridge);
    var timeout = setTimeout(function () { finish(new Error('The root service did not respond. Check Homebrew Channel.')); }, 20000);
    function finish(error, result) {
      if (completed) { return; }
      completed = true;
      clearTimeout(timeout);
      var index = bridges.indexOf(bridge);
      if (index !== -1) { bridges.splice(index, 1); }
      callback(error, result);
    }
    bridge.onservicecallback = function (response) {
      try {
        var outer = JSON.parse(response), inner;
        if (!outer.stdoutString) { throw new Error(outer.errorText || 'Homebrew root execution is unavailable.'); }
        inner = JSON.parse(outer.stdoutString);
        if (!inner.returnValue) { throw new Error(inner.errorText || 'The service could not complete the action.'); }
        finish(null, inner);
      } catch (error) { finish(error); }
    };
    try {
      bridge.call('luna://org.webosbrew.hbchannel.service/exec', JSON.stringify({command: '/usr/bin/python -B ' + quote(path + '/native/control.py') + ' ' + quote(action)}));
    } catch (error) { finish(error); }
  }
  function execute(action) {
    if (busy) { return; }
    epoch += 1;
    busy = true; setEnabled(false);
    message(action === 'status' ? 'Checking service status…' : 'Applying changes…', false);
    call(action, function (error, value) {
      busy = false;
      if (error) {
        message(error.message, true);
        if (!current) { text('status', 'Unavailable'); el('status-dot').className = 'dot error'; }
        setEnabled(!!current);
        return;
      }
      render(value);
      message(value.running ? 'Service is running. You can close this app.' : 'Service is stopped.', false);
      if (!document.activeElement || document.activeElement === document.body || document.activeElement.disabled) {
        el(value.running ? 'stop' : 'start').focus();
      }
    });
  }
  ['start','stop','restart'].forEach(function (action) { el(action).onclick = function () { execute(action); }; });
  ['alt3','alt2'].forEach(function (value) { el(value).onclick = function () { execute('strategy-' + value); }; });
  function closePicker() { el('strategy-picker').hidden = true; pickerInput = ''; el('all-strategies').focus(); }
  function chooseStrategy(choice) {
    if (busy || !current) { return; }
    closePicker(); execute('strategy-' + choice.id);
  }
  choices.forEach(function (choice) {
    var button = document.createElement('button');
    button.id = 'choice-' + choice.id; button.className = 'strategy-choice'; button.disabled = true;
    button.setAttribute('aria-pressed', 'false');
    button.textContent = ('0' + choice.number).slice(-2) + '  ' + choice.label;
    button.onclick = function () { chooseStrategy(choice); };
    el('strategy-options').appendChild(button);
  });
  el('all-strategies').onclick = function () {
    pickerInput = ''; text('picker-input', 'Select a strategy'); el('strategy-picker').hidden = false;
    var selected = choices.filter(function (choice) { return current && choice.id === current.strategy; })[0] || choices[0];
    if (selected) { el('choice-' + selected.id).focus(); el('choice-' + selected.id).scrollIntoView(false); }
  };
  el('picker-close').onclick = closePicker;
  el('autostart').onclick = function () { if (current) { execute(current.autostart ? 'autostart-off' : 'autostart-on'); } };
  el('refresh').onclick = function () { execute('status'); };
  el('log-toggle').onclick = function () {
    el('details').hidden = !el('details').hidden;
    text('log-toggle', el('details').hidden ? '6 Show details' : '6 Hide details');
    if (!el('details').hidden) { el('details').scrollIntoView(false); }
  };
  Array.prototype.forEach.call(document.querySelectorAll('button'), function (button) {
    button.onmouseover = function () { if (!button.disabled) { button.focus(); } };
  });
  function activate(id) {
    var button = el(id);
    if (button && !button.disabled) { button.focus(); button.click(); }
  }
  document.addEventListener('keydown', function (event) {
    var code = event.keyCode || event.which;
    if (code === 461 || code === 27) {
      event.preventDefault(); if (!el('strategy-picker').hidden) { closePicker(); } else { window.close(); } return;
    }
    var number = code >= 48 && code <= 57 ? code - 48 : code >= 96 && code <= 105 ? code - 96 : -1;
    if (!el('strategy-picker').hidden && (number >= 0 || (code === 13 && pickerInput))) {
      event.preventDefault(); if (event.repeat) { return; }
      if (number >= 0) { pickerInput += String(number); text('picker-input', 'Strategy number: ' + pickerInput); }
      if (pickerInput.length === 2 || code === 13) {
        var choice = choices.filter(function (item) { return item.number === parseInt(pickerInput, 10); })[0];
        if (choice) { chooseStrategy(choice); } else { text('picker-input', 'Enter a number from 01 to 22'); pickerInput = ''; }
      }
      return;
    }
    var shortcut = {0:'refresh', 1:'alt3', 2:'alt2', 3:'start', 4:'stop', 5:'restart', 6:'log-toggle', 7:'all-strategies'}[number];
    if (shortcut) { event.preventDefault(); if (!event.repeat) { activate(shortcut); } return; }
    if (code === 13) {
      event.preventDefault();
      if (!event.repeat && document.activeElement && document.activeElement.tagName === 'BUTTON') { activate(document.activeElement.id); }
      return;
    }
    if (code < 37 || code > 40) { return; }
    event.preventDefault();
    var focused = document.activeElement;
    if (!focused || focused.tagName !== 'BUTTON') { el('log-toggle').focus(); return; }
    var box = focused.getBoundingClientRect(), x = box.left + box.width / 2, y = box.top + box.height / 2;
    var buttons = document.querySelectorAll((el('strategy-picker').hidden ? '' : '#strategy-picker ') + 'button:not(:disabled)'), best = null, distance = Infinity;
    Array.prototype.forEach.call(buttons, function (button) {
      if (button === focused || !button.offsetWidth) { return; }
      var rect = button.getBoundingClientRect(), dx = rect.left + rect.width / 2 - x, dy = rect.top + rect.height / 2 - y;
      var forward = code === 37 ? -dx : code === 39 ? dx : code === 38 ? -dy : dy;
      var side = code === 37 || code === 39 ? Math.abs(dy) : Math.abs(dx);
      var score = forward + side * 2;
      if (forward > 5 && score < distance) { distance = score; best = button; }
    });
    if (best) { best.focus(); if (!el('strategy-picker').hidden) { best.scrollIntoView(false); } }
  });
  execute('status');
  setInterval(function () {
    if (busy) { return; }
    var requestEpoch = epoch;
    call('status', function (error, value) {
      if (!error && !busy && requestEpoch === epoch) {
        render(value);
        message(value.running ? 'Service is running. You can close this app.' : 'Service is stopped.', false);
      }
    });
  }, 5000);
}());
