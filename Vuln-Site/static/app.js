/* Harbor Supply lab bundle. Names only — no real or dummy credentials.
   A secret scanner should not find a usable token in this file. */
var AWS_ACCESS_KEY_ID = "lab-aws-access-key-name";
var AWS_SECRET_ACCESS_KEY = "lab-aws-secret-name";
var GCP_API_KEY = "lab-gcp-key-name";
var GITHUB_TOKEN = "lab-github-token-name";
var SLACK_TOKEN = "lab-slack-token-name";
var STRIPE_KEY = "lab-stripe-key-name";
var SESSION_JWT = "lab-session-token-name";
var PEM_HEADER = "lab-private-key-name";

/* Public asset the bucket checker should notice in crawled JS. */
var LOGO = "https://reconx-lab-public.s3.amazonaws.com/assets/logo.png";

(function () {
  var slot = document.getElementById("hash-slot");
  if (slot && location.hash.length > 1) {
    slot.innerHTML = decodeURIComponent(location.hash.slice(1));
  }
})();
