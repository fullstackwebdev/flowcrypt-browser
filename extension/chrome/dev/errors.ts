/* © 2016-2018 FlowCrypt Limited. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { Catch } from "./../../js/common/common.js";
import { Xss, Ui } from '../../js/common/browser.js';
import { Store } from "../../js/common/store.js";

Catch.try(async () => {

  let storage = await Store.getGlobal(['errors']);
  if (storage.errors && storage.errors.length > 0) {
    let errors = ('<p>' + storage.errors.join('</p><br/><p>') + '</p>').replace(/\n/g, '<br>');
    Xss.sanitizeRender('.pre', errors);
  }

  $('.clear').click(Ui.event.handle(async () => {
    await Store.remove(null, ['errors']);
    window.location.reload();
  }));

})();