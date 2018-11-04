/* © 2016-2018 FlowCrypt Limited. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { Store } from '../../../js/common/store.js';
import { Catch, Env, Dict } from '../../../js/common/common.js';
import { Att } from '../../../js/common/att.js';
import { Xss, Ui, XssSafeFactory } from '../../../js/common/browser.js';
import { BrowserMsg } from '../../../js/common/extension.js';
import { Pgp } from '../../../js/common/pgp.js';

Catch.try(async () => {

  let urlParams = Env.urlParams(['acctEmail', 'parentTabId']);
  let acctEmail = Env.urlParamRequire.string(urlParams, 'acctEmail');
  let parentTabId = Env.urlParamRequire.string(urlParams, 'parentTabId');

  let tabId = await BrowserMsg.requiredTabId();

  let factory = new XssSafeFactory(acctEmail, tabId, undefined, undefined, {compact: true});
  let backBtn = '<a href="#" id="page_back_button" data-test="action-back-to-contact-list">back</a>';
  let space = '&nbsp;&nbsp;&nbsp;&nbsp;';

  BrowserMsg.listen({}, tabId); // set_css

  let renderContactList = async () => {
    let contacts = await Store.dbContactSearch(null, { has_pgp: true });

    Xss.sanitizeRender('.line.actions', '&nbsp;&nbsp;<a href="#" class="action_export_all">export all</a>&nbsp;&nbsp;').find('.action_export_all').click(Ui.event.prevent('double', (self) => {
      let allArmoredPublicKeys = contacts.map(c => (c.pubkey || '').trim()).join('\n');
      let exportFile = new Att({name: 'public-keys-export.asc', type: 'application/pgp-keys', data: allArmoredPublicKeys});
      Att.methods.saveToDownloads(exportFile, Env.browser().name === 'firefox' ? $('.line.actions') : null);
    }));

    Xss.sanitizeAppend('.line.actions', '&nbsp;&nbsp;<a href="#" class="action_view_bulk_import">import public keys</a>&nbsp;&nbsp;').find('.action_view_bulk_import').off().click(Ui.event.prevent('double', (self) => {
      $('.hide_when_rendering_subpage').css('display', 'none');
      Xss.sanitizeRender('h1', `${backBtn}${space}Bulk Public Key Import${space}`);
      $('#bulk_import').css('display', 'block');
      $('#bulk_import .input_pubkey').val('').css('display', 'inline-block');
      $('#bulk_import .action_process').css('display', 'inline-block');
      $('#bulk_import #processed').text('').css('display', 'none');
      $('#page_back_button').click(Ui.event.handle(() => renderContactList()));
    }));

    $('table#emails').text('');
    $('div.hide_when_rendering_subpage').css('display', 'block');
    $('table.hide_when_rendering_subpage').css('display', 'table');
    $('h1').text('Contacts and their Public Keys');
    $('#view_contact, #edit_contact, #bulk_import').css('display', 'none');

    let tableContents = '';
    for (let c of contacts) {
      let e = Xss.htmlEscape(c.email);
      let show = `<a href="#" class="action_show" data-test="action-show-pubkey"></a>`;
      let change = `<a href="#" class="action_change" data-test="action-change-pubkey"></a>`;
      let remove = `<a href="#" class="action_remove" data-test="action-remove-pubkey"></a>`;
      tableContents += `<tr email="${e}"><td>${e}</td><td>${show}</td><td>${change}</td><td>${remove}</td></tr>`;
    }
    Xss.sanitizeReplace('table#emails', `<table id="emails" class="hide_when_rendering_subpage">${tableContents}</table>`);

    $('a.action_show').off().click(Ui.event.prevent('double', async (self) => {
      let [contact] = await Store.dbContactGet(null, [$(self).closest('tr').attr('email')!]); // defined above
      $('.hide_when_rendering_subpage').css('display', 'none');
      Xss.sanitizeRender('h1', `'${backBtn}${space}${contact!.email}`); // should exist - from list of contacts
      if (contact!.client === 'cryptup') {
        Xss.sanitizeAppend('h1', '&nbsp;&nbsp;&nbsp;&nbsp;<img src="/img/logo/flowcrypt-logo-19-19.png" />');
      } else {
        Xss.sanitizeAppend('h1', '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;');
      }
      $('#view_contact .key_dump').text(contact!.pubkey!); // should exist - from list of contacts && should have pgp - filtered
      $('#view_contact .key_fingerprint').text(contact!.fingerprint!); // should exist - from list of contacts && should have pgp - filtered
      $('#view_contact .key_words').text(contact!.keywords!); // should exist - from list of contacts && should have pgp - filtered
      $('#view_contact').css('display', 'block');
      $('#page_back_button').click(Ui.event.handle(() => renderContactList()));
    }));

    $('a.action_change').off().click(Ui.event.prevent('double', self => {
      $('.hide_when_rendering_subpage').css('display', 'none');
      let email = $(self).closest('tr').attr('email')!;
      Xss.sanitizeRender('h1', `${backBtn}${space}${Xss.htmlEscape(email)}${space}(edit)`);
      $('#edit_contact').css('display', 'block');
      $('#edit_contact .input_pubkey').val('').attr('email', email);
      $('#page_back_button').click(Ui.event.handle(() => renderContactList()));
    }));

    $('#edit_contact .action_save_edited_pubkey').off().click(Ui.event.prevent('double', async (self) => {
      let armoredPubkey = $('#edit_contact .input_pubkey').val() as string; // textarea
      let email = $('#edit_contact .input_pubkey').attr('email');
      if (!armoredPubkey || !email) {
        alert('No public key entered');
      } else if (Pgp.key.fingerprint(armoredPubkey) !== null) {
        await Store.dbContactSave(null, Store.dbContactObj(email, null, 'pgp', armoredPubkey, null, false, Date.now()));
        await renderContactList();
      } else {
        alert('Cannot recognize a valid public key, please try again. Let me know at human@flowcrypt.com if you need help.');
        $('#edit_contact .input_pubkey').val('').focus();
      }
    }));

    $('.action_view_bulk_import').off().click(Ui.event.prevent('double', self => {
      $('.hide_when_rendering_subpage').css('display', 'none');
      Xss.sanitizeRender('h1', `${backBtn}${space}Bulk Public Key Import${space}`);
      $('#bulk_import').css('display', 'block');
      $('#bulk_import .input_pubkey').val('').css('display', 'inline-block');
      $('#bulk_import .action_process').css('display', 'inline-block');
      $('#bulk_import #processed').text('').css('display', 'none');
      $('#page_back_button').click(Ui.event.handle(() => renderContactList()));
    }));

    $('#bulk_import .action_process').off().click(Ui.event.prevent('double', self => {
      let replacedHtmlSafe = Pgp.armor.replace_blocks(factory, $('#bulk_import .input_pubkey').val() as string); // textarea
      if (!replacedHtmlSafe || replacedHtmlSafe === $('#bulk_import .input_pubkey').val()) {
        alert('Could not find any new public keys');
      } else {
        $('#bulk_import #processed').html(replacedHtmlSafe).css('display', 'block'); // xss-safe-factory
        $('#bulk_import .input_pubkey, #bulk_import .action_process').css('display', 'none');
      }
    }));

    $('a.action_remove').off().click(Ui.event.prevent('double', async (self) => {
      await Store.dbContactSave(null, Store.dbContactObj($(self).closest('tr').attr('email')!, null, null, null, null, false, null));
      await renderContactList();
    }));

  };

  await renderContactList();

})();