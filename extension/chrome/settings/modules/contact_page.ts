/* © 2016-2018 FlowCrypt Limited. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { Store, Serializable } from '../../../js/common/store.js';
import { Value, Str, Dict } from '../../../js/common/common.js';
import { Att } from '../../../js/common/att.js';
import { Xss, Ui, AttUI, Env } from '../../../js/common/browser.js';
import { BrowserMsg } from '../../../js/common/extension.js';
import { Settings } from '../../../js/common/settings.js';
import { Api, R } from '../../../js/common/api.js';
import { Lang } from '../../../js/common/lang.js';
import { Catch } from '../../../js/common/catch.js';

Catch.try(async () => {

  const urlParams = Env.urlParams(['acctEmail', 'parentTabId']);
  const acctEmail = Env.urlParamRequire.string(urlParams, 'acctEmail');
  const parentTabId = Env.urlParamRequire.string(urlParams, 'parentTabId');

  const attachJs = new AttUI(() => ({ size_mb: 5, size: 5 * 1024 * 1024, count: 1 }));
  let newPhotoFile: Att;

  const S = Ui.buildJquerySels({
    'status': '.status',
    'subscribe': '.action_subscribe',
    'hide_if_active': '.hide_if_active',
    'show_if_active': '.show_if_active',
    'input_email': '.input_email',
    'input_name': '.input_name',
    'input_intro': '.input_intro',
    'input_alias': '.input_alias',
    'action_enable': '.action_enable',
    'action_update': '.action_update',
    'action_close': '.action_close',
    'management_account': '.management_account',
    'photo': '.profile_photo img',
  });

  const renderFields = (result: R.FcAccountUpdate$result) => {
    if (result.alias) {
      const me = Api.fc.url('me', result.alias);
      const meEscaped = Xss.escape(me);
      const meEscapedDisplay = Xss.escape(me.replace('https://', ''));
      Xss.sanitizeRender(S.cached('status'), `Your contact page is currently <b class="good">enabled</b> at <a href="${meEscaped}" target="_blank">${meEscapedDisplay}</a></span>`);
      S.cached('hide_if_active').css('display', 'none');
      S.cached('show_if_active').css('display', 'inline-block');
      S.cached('input_email').val(result.email);
      S.cached('input_intro').val(result.intro);
      S.cached('input_alias').val(result.alias);
      S.cached('input_name').val(result.name);
      if (result.photo) {
        S.cached('photo').attr('src', result.photo);
      }
      attachJs.initAttDialog('fineuploader', 'select_photo');
      attachJs.setAttAddedCb((file: Att) => {
        newPhotoFile = file;
        Xss.sanitizeReplace('#select_photo', Ui.e('span', { text: file.name }));
      });
    } else {
      S.cached('management_account').text(result.email).parent().removeClass('display_none');
      Xss.sanitizeRender(S.cached('status'), 'Your contact page is currently <b class="bad">disabled</b>. <a href="#" class="action_enable">Enable contact page</a>');
      S.now('action_enable').click(Ui.event.prevent('double', enableContactPage));
    }
  };

  const enableContactPage = async () => {
    Xss.sanitizeRender(S.cached('status'), 'Enabling..' + Ui.spinner('green'));
    const authInfo = await Store.authInfo();
    const storage = await Store.getAcct(authInfo.acctEmail!, ['full_name']);
    try {
      const alias = await findAvailableAlias(authInfo.acctEmail!);
      const initial = { alias, name: storage.full_name || Str.capitalize(authInfo.acctEmail!.split('@')[0]), intro: 'Use this contact page to send me encrypted messages and files.' };
      const response = await Api.fc.accountUpdate(initial);
      if (!response.updated) {
        alert('Failed to enable your Contact Page. Please try again');
      }
      window.location.reload();
    } catch (e) {
      Catch.handleErr(e);
      alert(`Failed to create account, possibly a network issue. Please try again.\n\n${String(e)}`);
      window.location.reload();
    }
  };

  S.cached('action_update').click(Ui.event.prevent('double', async () => {
    if (!S.cached('input_name').val()) {
      alert('Please add your name');
    } else if (!S.cached('input_intro').val()) {
      alert('Please add intro text');
    } else {
      S.cached('show_if_active').css('display', 'none');
      Xss.sanitizeRender(S.cached('status'), 'Updating ' + Ui.spinner('green'));
      const update: Dict<Serializable> = { name: S.cached('input_name').val(), intro: S.cached('input_intro').val() };
      if (newPhotoFile) {
        update.photo_content = btoa(newPhotoFile.asText());
      }
      await Api.fc.accountUpdate(update);
      window.location.reload();
    }
  }));

  S.cached('action_close').click(Ui.event.handle(() => BrowserMsg.send.closePage(parentTabId)));

  const findAvailableAlias = async (email: string): Promise<string> => {
    let alias = email.split('@')[0].replace(/[^a-z0-9]/g, '');
    while (alias.length < 3) {
      alias += Str.sloppyRandom(1).toLowerCase();
    }
    let i = 0;
    while (true) {
      alias += (i || '');
      const response = await Api.fc.linkMe(alias);
      if (!response.profile) {
        return alias;
      }
      i += Value.int.lousyRandom(1, 9);
    }
  };

  Xss.sanitizeRender(S.cached('status'), 'Loading..' + Ui.spinner('green'));
  try {
    const response = await Api.fc.accountUpdate();
    renderFields(response.result);
  } catch (e) {
    if (Api.err.isAuthErr(e)) {
      Xss.sanitizeRender(S.cached('status'), `${Lang.account.verifyToSetUpContactPage} <a href="#" class="action_subscribe">Get trial</a>`);
      S.now('subscribe').click(Ui.event.handle(() => Settings.redirectSubPage(acctEmail, parentTabId, '/chrome/elements/subscribe.htm', '&source=authErr')));
    } else {
      S.cached('status').text('Failed to load your Contact Page settings. Please try to reload this page. Let me know at human@flowcrypt.com if this persists.');
    }
  }

})();