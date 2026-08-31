/**
 * server.js
 *
 * Small backend server that does the ONE thing the Flutter app
 * itself cannot safely do: delete other users' Firebase Auth
 * accounts. It exposes a single HTTP endpoint that the admin panel
 * calls when "Clear All Data" is pressed.
 *
 * Deployed for free on Render.com — no credit card needed, and
 * this server itself never touches your Firebase billing plan
 * (Spark/free plan is fine).
 *
 * WHAT IT DELETES:
 *   Every document in Firestore 'users' EXCEPT the calling admin's
 *   own document — this includes students AND staff (advisor, hod,
 *   principal, security) — matching the app's "Clear All Data"
 *   behaviour exactly. For each of them:
 *     1. Delete their Firebase Auth account
 *     2. Delete their 'users' document
 *   Then delete every document in 'loginIndex' (all of it).
 *
 * SECURITY:
 *   - The endpoint requires a valid Firebase ID token in the
 *     Authorization header (Authorization: Bearer <token>).
 *   - It looks up that user's Firestore users/{uid} doc and only
 *     proceeds if role == 'admin'. Anyone else gets 403 Forbidden.
 *   - The Firebase service account credentials are read from an
 *     ENVIRONMENT VARIABLE (FIREBASE_SERVICE_ACCOUNT_JSON), never
 *     from a file committed to the repo.
 */

const express = require('express');
const cors = require('cors');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const { getAuth } = require('firebase-admin/auth');

const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

if (!serviceAccountJson) {
  console.error(
    'FIREBASE_SERVICE_ACCOUNT_JSON environment variable is not set.',
  );
  process.exit(1);
}

const serviceAccount = JSON.parse(serviceAccountJson);

initializeApp({
  credential: cert(serviceAccount),
});

const db = getFirestore();
const auth = getAuth();

const app = express();
app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.send('Clear-student-data backend is running.');
});

// ----------------------------------------------------------------
// POST /clear-student-data
// Header required: Authorization: Bearer <Firebase ID token>
// Deletes EVERY non-admin user (students + staff) — Auth account
// + their Firestore docs — and clears the whole loginIndex.
// ----------------------------------------------------------------
app.post('/clear-student-data', async (req, res) => {
  try {
    // ------------------------------------------------------
    // STEP 0: Verify the caller is a signed-in admin
    // ------------------------------------------------------
    const authHeader = req.headers.authorization || '';
    const idToken = authHeader.startsWith('Bearer ')
      ? authHeader.slice('Bearer '.length)
      : null;

    if (!idToken) {
      return res.status(401).json({ error: 'Missing Authorization header.' });
    }

    let decodedToken;
    try {
      decodedToken = await auth.verifyIdToken(idToken);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired token.' });
    }

    const callerUid = decodedToken.uid;
    const callerDoc = await db.collection('users').doc(callerUid).get();

    if (!callerDoc.exists || callerDoc.data().role !== 'admin') {
      return res
        .status(403)
        .json({ error: 'Only admin accounts can perform this action.' });
    }

    // ------------------------------------------------------
    // STEP 1: Find every 'users' doc EXCEPT the calling admin
    // (students, advisors, hods, principals, security, and
    // even other admin accounts — matches the app's own
    // _deleteCollection('users', adminUid) behaviour, which
    // only ever protects the CURRENTLY LOGGED IN admin).
    // ------------------------------------------------------
    const usersSnapshot = await db.collection('users').get();

    const targetUids = [];
    const userDocRefs = [];

    usersSnapshot.forEach((doc) => {
      if (doc.id === callerUid) return; // never delete the caller
      targetUids.push(doc.id);
      userDocRefs.push(doc.ref);
    });

    // ------------------------------------------------------
    // STEP 2: Delete their Firebase Auth accounts
    // ------------------------------------------------------
    let authDeleted = 0;
    let authFailed = 0;

    if (targetUids.length > 0) {
      const BATCH_SIZE = 1000;
      for (let i = 0; i < targetUids.length; i += BATCH_SIZE) {
        const chunk = targetUids.slice(i, i + BATCH_SIZE);
        const result = await auth.deleteUsers(chunk);
        authDeleted += result.successCount;
        authFailed += result.failureCount;
      }
    }

    // ------------------------------------------------------
    // STEP 3: Delete their 'users' documents
    // ------------------------------------------------------
    const deletedUserDocs = await deleteDocsInBatches(userDocRefs);

    // ------------------------------------------------------
    // STEP 4: Delete ALL of 'loginIndex' (students only ever
    // appear here per the app's schema, so clearing all of it
    // is correct and matches the app's own behaviour).
    // ------------------------------------------------------
    const loginIndexSnapshot = await db.collection('loginIndex').get();
    const loginIndexDocRefs = [];
    loginIndexSnapshot.forEach((doc) => loginIndexDocRefs.push(doc.ref));

    const deletedLoginIndexDocs =
      await deleteDocsInBatches(loginIndexDocRefs);

    return res.json({
      success: true,
      authDeleted,
      authFailed,
      deletedUserDocs,
      deletedLoginIndexDocs,
    });
  } catch (err) {
    console.error('clear-student-data failed:', err);
    return res.status(500).json({ error: err.message || 'Unknown error.' });
  }
});

async function deleteDocsInBatches(docRefs) {
  const BATCH_SIZE = 400;
  let deletedCount = 0;

  for (let i = 0; i < docRefs.length; i += BATCH_SIZE) {
    const chunk = docRefs.slice(i, i + BATCH_SIZE);
    const batch = db.batch();
    chunk.forEach((ref) => batch.delete(ref));
    await batch.commit();
    deletedCount += chunk.length;
  }

  return deletedCount;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
