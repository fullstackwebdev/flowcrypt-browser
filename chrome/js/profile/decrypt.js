
// chrome-extension://pfahhfljflkjoeghhmmjkiaimhignbmh/js/profile/decrypt.htm

let url = 'chrome-extension://pfahhfljflkjoeghhmmjkiaimhignbmh/chrome/elements/pgp_block.htm?account_email=flowcrypt.compatibility%40gmail.com&message=-----BEGIN%20PGP%20MESSAGE-----%0D%0AVersion%3A%20FlowCrypt%205.2.0%20Gmail%20Encryption%20flowcrypt.com%0D%0AComment%3A%20Seamlessly%20send%2C%20receive%20and%20search%20encrypted%20email%0D%0A%0D%0AwcFMA0taL%2FzmLZUBARAArdbyWcgwf3B0LjUD0ephMVsbwKMqETPnpCZiXnuk%0AXWEfNv0IbbuH3Z3MT%2FDmMQuzjltFOx7ggKAg3z452JZI%2FZ74vxaMtiWL%2F4NB%0AbDERSYIsLe%2FqaG0r9bLSFgju2JpToUGY6yiEYg9ciE1vitUwzurx%2BwFi7WIq%0AsO%2Bzra46rp76rUKk%2Fvss6CtPlqScNyJTBmv%2FSz%2BL4zbMESkdiR5qBVqm5ah6%0A65TXO1KIH2ZjdOBmLOEi4p3%2FJM6IQ2iPQQIsxWHjqtMQyOZA9Q40GpRT5kQ7%0ADCUXsRsGB5YjfgsBw2r8HUt2eLKmUThPC%2FQZlu8yLO1AAIAPJJtwAw6OOJTR%0ATxBTwMAhcJxtFRKPYtUD87xuydctGhoLy6mJiPk3q2Z4BP5hctnuSsaUQPl%2F%0ACsZnSyobQIde5MnS3GyEQ%2BMUc0oq94aTS8OdXrX3EJJU1EU3Zy1P38n3V%2Bgy%0AW1qH5CR1D8otQ8Ed9Ks%2BSRiNm%2FQPBo8hu3df5RGQycwVe%2Bbmx3EDCSBq%2BzbD%0ASbaViUJaKxJnqJ%2BUKEruouuhli1EkzVgSj%2BnpQjJ1EcVIjPGNE57BDC0qIF9%0AbcHcCsyT%2B8VMtrCB9aMAUGNXr%2BbyhY8SIv0xFdTshjx5M6PWu7e6yFrRiT2d%0A4mMUJjYMWcEyXd3RH9pn1QLEWZK1Fpaclb8oPi4PwHzSPQEeLXuhArWpS%2Fsv%0AkqaG2U1x8qUu3yM3vkxWWRRMtmRuPTvFfLhoJRqxGV%2FihBIEQXwlKvgG5qcW%0AjP%2FPXN0%3D%0D%0A%3DNyoF%0D%0A-----END%20PGP%20MESSAGE-----%0D%0A';
let iframe = '<iframe src="' + url + '"></iframe><br>';

$('#start').click(() => {
  for(let i = 0; i < 50; i++) {
  // for(let i = 0; i < 20; i++) {
  // for(let i = 0; i < 1; i++) {
    $('#messages').prepend(iframe);
  }
});
