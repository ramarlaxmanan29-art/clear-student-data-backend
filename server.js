/**
 * server.js
 *
 * Backend that does the things the Flutter app itself cannot
 * safely do on its own:
 *   1. POST /clear-student-data  — delete non-admin Auth accounts
 *   2. POST /change-admin-email  — instantly change the calling
 *      admin's own email (no "click the verification link" step)
 *
 * Deployed for free on Render.com — no credit card needed, and
 * this server itself never touches your Firebase billing plan
 * (Spark/free plan is fine).
 *
 * SECURITY (both endpoints):
 *   - Require a valid Firebase ID token in the Authorization
 *     header (Authorization: Bearer <token>).
 *   - Look up that user's Firestore users/{uid} doc and only
 *     proceed if role == 'admin'. Anyone else gets 403 Forbidden.
 *   - Firebase service account credentials are read from an
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
// Shared helper: verify the caller is a signed-in admin.
// Returns { callerUid } on success, or sends an error response and
// returns null (caller should just `return` when this is null).
// ----------------------------------------------------------------
async function requireAdmin(req, res) {
  const authHeader = req.headers.authorization || '';
  const idToken = authHeader.startsWith('Bearer ')
    ? authHeader.slice('Bearer '.length)
    : null;

  if (!idToken) {
    res.status(401).json({ error: 'Missing Authorization header.' });
    return null;
  }

  let decodedToken;
  try {
    decodedToken = await auth.verifyIdToken(idToken);
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token.' });
    return null;
  }

  const callerUid = decodedToken.uid;
  const callerDoc = await db.collection('users').doc(callerUid).get();

  if (!callerDoc.exists || callerDoc.data().role !== 'admin') {
    res
      .status(403)
      .json({ error: 'Only admin accounts can perform this action.' });
    return null;
  }

  return { callerUid, callerData: callerDoc.data() };
}

// ----------------------------------------------------------------
// POST /clear-student-data
// Header required: Authorization: Bearer <Firebase ID token>
// Deletes EVERY non-admin user (students + staff) — Auth account
// + their Firestore docs — and clears the whole loginIndex.
// ----------------------------------------------------------------
app.post('/clear-student-data', async (req, res) => {
  try {
    const adminInfo = await requireAdmin(req, res);
    if (!adminInfo) return;
    const { callerUid } = adminInfo;

    // ------------------------------------------------------
    // STEP 1: Find every 'users' doc EXCEPT the calling admin
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
    // STEP 4: Delete ALL of 'loginIndex'
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

// ----------------------------------------------------------------
// POST /change-admin-email
// Header required: Authorization: Bearer <Firebase ID token>
// Body: { "oldEmail": "...", "newEmail": "..." }
//
// Instantly changes the CALLING admin's own email — no
// verification link needs to be clicked, because this uses the
// Admin SDK (server-side, trusted), not the client SDK.
// ----------------------------------------------------------------
app.post('/change-admin-email', async (req, res) => {
  try {
    const adminInfo = await requireAdmin(req, res);
    if (!adminInfo) return;
    const { callerUid, callerData } = adminInfo;

    const oldEmail = (req.body?.oldEmail || '').trim().toLowerCase();
    const newEmail = (req.body?.newEmail || '').trim().toLowerCase();

    if (!oldEmail || !newEmail) {
      return res
        .status(400)
        .json({ error: 'Both oldEmail and newEmail are required.' });
    }

    const currentEmailOnRecord = (callerData.email || '').trim().toLowerCase();

    if (oldEmail !== currentEmailOnRecord) {
      return res.status(400).json({
        error: 'Old email does not match your current account email.',
      });
    }

    if (newEmail === oldEmail) {
      return res
        .status(400)
        .json({ error: 'New email must be different from the old email.' });
    }

    // ------------------------------------------------------
    // Update Firebase Auth email immediately (Admin SDK bypasses
    // the "verify before update" requirement the client SDK has).
    // ------------------------------------------------------
    await auth.updateUser(callerUid, { email: newEmail });

    // ------------------------------------------------------
    // Keep Firestore users/{uid}.email in sync.
    // ------------------------------------------------------
    await db.collection('users').doc(callerUid).update({
      email: newEmail,
    });

    return res.json({ success: true, newEmail });
  } catch (err) {
    console.error('change-admin-email failed:', err);

    if (err.code === 'auth/email-already-exists') {
      return res
        .status(400)
        .json({ error: 'That email is already in use by another account.' });
    }

    if (err.code === 'auth/invalid-email') {
      return res.status(400).json({ error: 'That email address is invalid.' });
    }

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
