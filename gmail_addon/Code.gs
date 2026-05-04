/**
 * Gmail Add-on: analyzes the currently open email for phishing indicators.
 *
 * Flow: Gmail triggers buildMessageCard() → we reconstruct a minimal RFC 822
 * message with all available headers → POST to FastAPI /analyze → render result
 * as a Card in the Gmail side panel.
 *
 * The FastAPI backend must be running locally and exposed via ngrok.
 */

/** Permanent ngrok static domain — no need to change this between sessions. */
var DEFAULT_API_BASE = 'https://saturday-province-confined.ngrok-free.dev';

/**
 * Allows overriding the API URL via Script Properties (key: PHISHING_API_BASE)
 * without editing the code. Falls back to DEFAULT_API_BASE if no property is set.
 */
function getApiBase_() {
  var props = PropertiesService.getScriptProperties();
  var base = props.getProperty('PHISHING_API_BASE');
  return (base && base.length) ? base.replace(/\/$/, '') : DEFAULT_API_BASE;
}

/**
 * Shown when the add-on is opened outside of a message context (e.g. from the
 * add-on homepage). Acts as a usage guide.
 */
function buildHomepageCard(e) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Phishing Detector'))
    .addSection(
      CardService.newCardSection()
        .setHeader('How to use')
        .addWidget(
          CardService.newTextParagraph().setText(
            'Open an email in Gmail. This add-on analyzes the current message ' +
              'and shows risk score and indicators from your backend API.'
          )
        )
    )
    .build();
}

/**
 * Main entry point — triggered automatically whenever the user opens an email.
 * Reconstructs an RFC 822-style message from Gmail API data and sends it for analysis.
 */
function buildMessageCard(e) {
  var accessToken = e.messageMetadata.accessToken;
  var messageId = e.messageMetadata.messageId;
  GmailApp.setCurrentMessageAccessToken(accessToken);
  var message = GmailApp.getMessageById(messageId);

  var subject = message.getSubject() || '';
  var from = message.getFrom() || '';

  // Prefer plain text — it's cleaner for keyword scanning.
  // Fall back to HTML if no plain-text body exists.
  var body = message.getPlainBody();
  if (!body || body.length < 2) {
    body = message.getBody() || '';
  }

  // Fetch all headers that drive the backend's advanced checks.
  // Wrapped in try/catch because some headers may not exist on every message.
  var replyTo = '';
  var returnPath = '';
  var authResults = '';
  var receivedSpf = '';
  try { replyTo = message.getReplyTo() || ''; } catch (e) {}
  try { returnPath = message.getHeader('Return-Path') || ''; } catch (e) {}
  try { authResults = message.getHeader('Authentication-Results') || ''; } catch (e) {}
  try { receivedSpf = message.getHeader('Received-SPF') || ''; } catch (e) {}

  // Build a minimal RFC 822 payload so the Python email parser can read all headers.
  // Only include optional headers when present to keep the payload clean.
  var rawEmail = 'From: ' + from + '\r\n' +
    'Subject: ' + subject + '\r\n';
  if (replyTo)     rawEmail += 'Reply-To: '                + replyTo     + '\r\n';
  if (returnPath)  rawEmail += 'Return-Path: '             + returnPath  + '\r\n';
  if (authResults) rawEmail += 'Authentication-Results: '  + authResults + '\r\n';
  if (receivedSpf) rawEmail += 'Received-SPF: '            + receivedSpf + '\r\n';
  rawEmail += 'MIME-Version: 1.0\r\n' +
    'Content-Type: text/plain; charset=UTF-8\r\n' +
    '\r\n' +
    body;

  var result = callAnalyzeApi_(rawEmail);
  return buildResultCard_(subject, from, result);
}

/**
 * POST the raw email to the FastAPI /analyze endpoint.
 * Returns the parsed JSON response, or an error object if the request fails.
 */
function callAnalyzeApi_(rawEmail) {
  var url = getApiBase_() + '/analyze';
  var options = {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify({ raw_email: rawEmail }),
    muteHttpExceptions: true,  // prevents Apps Script from throwing on non-2xx; we handle it below
  };
  try {
    var response = UrlFetchApp.fetch(url, options);
    var code = response.getResponseCode();
    var text = response.getContentText();
    if (code !== 200) {
      return { error: true, detail: 'HTTP ' + code + ': ' + text };
    }
    return JSON.parse(text);
  } catch (err) {
    return { error: true, detail: String(err) };
  }
}

/**
 * Render the analysis result (or error) as a Gmail side-panel Card.
 * Shows: message subject/sender, phishing verdict, risk score, and indicators.
 */
function buildResultCard_(subject, from, result) {
  var builder = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Phishing analysis'));

  // Message metadata section — lets the user confirm which email was scanned.
  var metaSection = CardService.newCardSection().setHeader('Message');
  metaSection.addWidget(CardService.newKeyValue().setTopLabel('Subject').setContent(subject || '(empty)'));
  metaSection.addWidget(CardService.newKeyValue().setTopLabel('From').setContent(from || '(unknown)'));
  builder.addSection(metaSection);

  // If the API call failed, show the error and stop.
  if (result.error) {
    builder.addSection(
      CardService.newCardSection()
        .setHeader('API error')
        .addWidget(CardService.newTextParagraph().setText(result.detail))
    );
    return builder.build();
  }

  var isPhishing = !!result.is_phishing;
  var score = typeof result.risk_score === 'number' ? result.risk_score : 0;
  var indicators = result.detected_indicators || [];

  var verdictSection = CardService.newCardSection().setHeader('Verdict');
  verdictSection.addWidget(
    CardService.newKeyValue().setTopLabel('Phishing')
      .setContent(isPhishing ? 'Likely / elevated risk' : 'Below threshold')
  );
  verdictSection.addWidget(
    CardService.newKeyValue().setTopLabel('Risk score').setContent(String(score) + ' / 100')
  );
  builder.addSection(verdictSection);

  var indSection = CardService.newCardSection().setHeader('Indicators');
  if (indicators.length === 0) {
    indSection.addWidget(CardService.newTextParagraph().setText('No indicators triggered.'));
  } else {
    var maxShow = 12;  // Gmail Cards have a height limit; truncate long lists gracefully
    for (var i = 0; i < indicators.length && i < maxShow; i++) {
      indSection.addWidget(CardService.newTextParagraph().setText('• ' + indicators[i]));
    }
    if (indicators.length > maxShow) {
      indSection.addWidget(
        CardService.newTextParagraph().setText('… and ' + (indicators.length - maxShow) + ' more.')
      );
    }
  }
  builder.addSection(indSection);

  return builder.build();
}
