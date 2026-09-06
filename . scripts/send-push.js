// scripts/send-push.js
//
// This is the piece that was missing: _notifyParent() in
// late_return_request_page.dart only WRITES a
// 'pendingPushNotifications' doc — a Flutter client can't call
// FCM's send API securely. This script reads those docs and
// actually sends the push, using the same service account already
// used by the Firestore cleanup script. Run it on a schedule via
// .github/workflows/send-push.yml.

const admin = require('firebase-admin');

const serviceAccountJson = Buffer.from(
  process.env.FIREBASE_SERVICE_ACCOUNT_B64,
  'base64',
).toString('utf-8');

const serviceAccount = JSON.parse(serviceAccountJson);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();
const messaging = admin.messaging();

const BATCH_LIMIT = 200;

function asString(value) {
  return value === undefined || value === null ? '' : String(value);
}

async function sendPendingPushes() {
  const snapshot = await db
    .collection('pendingPushNotifications')
    .where('sent', '==', false)
    .limit(BATCH_LIMIT)
    .get();

  if (snapshot.empty) {
    console.log('No pending push notifications.');
    return;
  }

  let successCount = 0;
  let failCount = 0;

  for (const doc of snapshot.docs) {
    const data = doc.data();
    const tokens = Array.isArray(data.tokens)
      ? data.tokens.filter((t) => typeof t === 'string' && t.length > 0)
      : [];

    if (tokens.length === 0) {
      console.log(
        `[${doc.id}] No tokens saved for this parent — marking as sent (nothing to send to).`,
      );
      await doc.ref.update({
        sent: true,
        sentAt: admin.firestore.FieldValue.serverTimestamp(),
        skippedNoTokens: true,
      });
      continue;
    }

    try {
      const response = await messaging.sendEachForMulticast({
        tokens,
        notification: {
          title: asString(data.title) || 'Notification',
          body: asString(data.body),
        },
        data: {
          type: asString(data.type),
          registerNumber: asString(data.registerNumber),
          outpassId: asString(data.outpassId),
        },
      });

      console.log(
        `[${doc.id}] Sent: ${response.successCount} success, ${response.failureCount} failed.`,
      );

      // Drop tokens FCM says are dead/unregistered so the parent's
      // users doc doesn't keep accumulating stale tokens.
      const deadTokens = [];
      response.responses.forEach((r, i) => {
        if (!r.success) {
          const code = r.error && r.error.code;
          if (
            code === 'messaging/registration-token-not-registered' ||
            code === 'messaging/invalid-registration-token'
          ) {
            deadTokens.push(tokens[i]);
          } else {
            console.error(
              `[${doc.id}] token ${i} failed: ${code || (r.error && r.error.message)}`,
            );
          }
        }
      });

      if (deadTokens.length > 0 && data.toUserId) {
        await db
          .collection('users')
          .doc(data.toUserId)
          .update({
            fcmTokens: admin.firestore.FieldValue.arrayRemove(...deadTokens),
          })
          .catch((e) =>
            console.error(
              `[${doc.id}] failed to prune dead tokens: ${e.message}`,
            ),
          );
      }

      await doc.ref.update({
        sent: true,
        sentAt: admin.firestore.FieldValue.serverTimestamp(),
        fcmSuccessCount: response.successCount,
        fcmFailureCount: response.failureCount,
      });

      successCount++;
    } catch (err) {
      console.error(`[${doc.id}] Failed to send:`, err.message);
      failCount++;
    }
  }

  console.log(`Done. ${successCount} sent, ${failCount} failed.`);
}

sendPendingPushes()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('Fatal error:', err);
    process.exit(1);
  });
