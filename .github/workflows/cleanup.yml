const admin = require('firebase-admin');

const serviceAccountJson = Buffer.from(
  process.env.FIREBASE_SERVICE_ACCOUNT_B64,
  'base64'
).toString('utf-8');

const serviceAccount = JSON.parse(serviceAccountJson);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

const COLLECTIONS = [
  'lateReturnRequests',
  'notifications',
  'pendingPushNotifications',
];

const BATCH_LIMIT = 200;

async function cleanupCollection(collectionName) {
  const cutoff = admin.firestore.Timestamp.now();

  const snapshot = await db
    .collection(collectionName)
    .where('expiresAt', '<=', cutoff)
    .limit(BATCH_LIMIT)
    .get();

  if (snapshot.empty) {
    console.log(`[${collectionName}] No expired docs found.`);
    return 0;
  }

  const batch = db.batch();
  snapshot.docs.forEach((doc) => batch.delete(doc.ref));
  await batch.commit();

  console.log(`[${collectionName}] Deleted ${snapshot.size} expired doc(s).`);
  return snapshot.size;
}

async function main() {
  let total = 0;
  for (const collectionName of COLLECTIONS) {
    try {
      total += await cleanupCollection(collectionName);
    } catch (err) {
      console.error(`[${collectionName}] Cleanup failed:`, err.message);
    }
  }
  console.log(`Total deleted: ${total}`);
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('Fatal error:', err);
    process.exit(1);
  });
