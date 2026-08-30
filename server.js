/**
 * server.js
 *
 * Small backend server that does the ONE thing the Flutter app
 * itself cannot safely do: delete other users' Firebase Auth
 * accounts. It exposes a single HTTP endpoint that the admin panel
 * calls when "Clear All Data" is pressed.
 *
 * Deployed for free on Render.com (or similar) — no credit card
 * needed, and this server itself never touches your Firebase
 * billing plan (Spark/free plan is fine).
 *
 * SECURITY:
 *   - The endpoint requires a valid Firebase ID token in the
 *     Authorization header (Authorization: Bearer <token>).
 *   - It looks up that user's Firestore users/{uid} doc and only
 *     proceeds if role == 'admin'. Anyone else gets 403 Forbidden.
 *   - The Firebase service account credentials are read from an
 *     ENVIRONMENT VARIABLE (FIREBASE_SERVICE_ACCOUNT_JSON), never
 *     from a file committed to your repo. Render lets you set
 *     environment variables privately in its dashboard.
 */

const express = require('express');
const cors = require('cors');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const { getAuth } = require('firebase-admin/auth');

// ----------------------------------------------------------------
// Firebase Admin init — credentials come from an environment
// variable set in the Render dashboard (see DEPLOY_INSTRUCTIONS.md).
// ----------------------------------------------------------------
const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

if (!serviceAccountJson) {
  console.error(
    'FIREBASE_SERVICE_ACCOUNT_JSON environment variable is not set. ' +
      'See DEPLOY_INSTRUCTIONS.md.',
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
app.use(cors()); // allows the Flutter web app to call this server
app.use(express.json());

// ----------------------------------------------------------------
// Health check — visiting the server's URL in a browser should
// show this, confirming the server is alive.
// ----------------------------------------------------------------
app.get('/', (req, res) => {
  res.send('Clear-student-data backend is running.');
});

// ----------------------------------------------------------------
// POST /clear-student-data
// Header required: Authorization: Bearer <Firebase ID token>
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
    // STEP 1: Find all student user docs (and their uids)
    // ------------------------------------------------------
    const usersSnapshot = await db
      .collection('users')
      .where('role', '==', 'student')
      .get();

    const studentUids = [];
    const userDocRefs = [];

    usersSnapshot.forEach((doc) => {
      studentUids.push(doc.id);
      userDocRefs.push(doc.ref);
    });

    // ------------------------------------------------------
    // STEP 2: Delete their Firebase Auth accounts
    // ------------------------------------------------------
    let authDeleted = 0;
    let authFailed = 0;

    if (studentUids.length > 0) {
      const BATCH_SIZE = 1000;
      for (let i = 0; i < studentUids.length; i += BATCH_SIZE) {
        const chunk = studentUids.slice(i, i + BATCH_SIZE);
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
    // STEP 4: Delete student entries in 'loginIndex'
    // ------------------------------------------------------
    const loginIndexSnapshot = await db
      .collection('loginIndex')
      .where('role', '==', 'student')
      .get();

    const loginIndexDocRefs = [];
    loginIndexSnapshot.forEach((doc) => loginIndexDocRefs.push(doc.ref));

    const deletedLoginIndexDocs =
      await deleteDocsInBatches(loginIndexDocRefs);

    // ------------------------------------------------------
    // DONE
    // ------------------------------------------------------
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
