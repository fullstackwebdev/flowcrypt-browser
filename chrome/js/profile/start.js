
'use strict';

window.flowcrypt_profile = {
  start: Date.now(),
  checkpoints: [],
  last: undefined,
  add: function (name) {
    let now = Date.now();
    this.checkpoints.push({name: name, ms: now - (this.last || this.start), cumulative: now - this.start});
    this.last = now;
  },
  print: function () {
    let r = this.checkpoints.map(o => o.ms + ' | ' + o.cumulative + ' | ' + o.name).join('\n');
    console.log(r);
    return r;
  },
};

window.flowcrypt_profile.add('start');
