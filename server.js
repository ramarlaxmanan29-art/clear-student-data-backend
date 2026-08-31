/**
 * server.js
 *
 * Backend that does the things the Flutter app itself cannot
 * safely do on its own:
 *   1. POST /clear-student-data       — delete non-admin Auth accounts
 *   2. POST /change-admin-email       — instantly change the calling
 *      admin's own email (no "click the verification link" step)
 *   3. POST /reset-student-password   — admin-approved student
 *      password reset (real Auth password change via Admin SDK)
 *   4. POST /student-reset-password   — student self-service reset
 *      using Register Number only (no admin login needed)
 *   5. POST /admin-reset-password     — admin self-service reset
 *      using Admin Name only (no admin login needed)
 *   6. POST /send-notification        — push a notification to one
 *      or more users' registered devices (any signed-in user)
 *
 * Deployed for free on Render.com — no credit card needed, and
 * this server itself never touches your Firebase billing plan
 * (Spark/free plan is fine).
 *
 * SECURITY:
 *   - Endpoints 1-3 require a valid Firebase ID token in the
 *     Authorization header (Authorization: Bearer <token>) and
 *     the caller's Firestore users/{uid} doc must have
 *     role == 'admin'.
 *   - Endpoints 4-5 are intentionally PUBLIC (no login token) —
 *     they exist specifically for "I forgot my password" recovery
 *     before the person can log in. They only need the Register
 *     Number / Admin Name to identify the account. There is no ID
 *     verification step, by explicit request.
 *   - Endpoint 6 requires a valid Firebase ID token, but from ANY
 *     signed-in user (student, staff, or admin) — every role can
 *     trigger a notification (advisor approves, student requests,
 *     security scans, etc.), not just admins.
 *   - Firebase service account credentials are read from an
 *     ENVIRONMENT VARIABLE (FIREBASE_SERVICE_ACCOUNT_JSON), never
 *     from a file committed to the repo.
 */

const express = require('express');
const cors = require('cors');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');
const { getAuth } = require('firebase-admin/auth');
const { getMessaging } = require('firebase-admin/messaging');

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
const messaging = getMessaging();

const app = express();
app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.send('Clear-student-data backend is running.');
});

// ----------------------------------------------------------------
// Shared helper: verify the caller is a signed-in admin.
// Returns { callerUid, callerData } on success, or sends an error
// response and returns null (caller should just `return` when
// this is null).
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
// Shared helper: verify the caller is ANY signed-in user (student,
// staff or admin). Used by /send-notification, since every role
// can trigger a notification — not just admins.
// ----------------------------------------------------------------
async function requireAuth(req, res) {
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

  return { callerUid: decodedToken.uid };
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

    await auth.updateUser(callerUid, { email: newEmail });

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

// ----------------------------------------------------------------
// POST /reset-student-password
// Header required: Authorization: Bearer <Firebase ID token>
// Body: { "registerNumber": "...", "newPassword": "..." }
//
// Admin verifies the student's uploaded ID card manually in the
// "Pending Requests" screen, then approves with a new password —
// this endpoint performs the actual Firebase Auth password change
// via the Admin SDK. The client (admin_dashboard.dart) then marks
// the request document as 'approved'.
// ----------------------------------------------------------------
app.post('/reset-student-password', async (req, res) => {
  try {
    const adminInfo = await requireAdmin(req, res);
    if (!adminInfo) return;

    const registerNumber = (req.body?.registerNumber || '')
      .trim()
      .toLowerCase();
    const newPassword = req.body?.newPassword || '';

    if (!registerNumber) {
      return res.status(400).json({ error: 'registerNumber is required.' });
    }

    if (newPassword.length < 6) {
      return res
        .status(400)
        .json({ error: 'newPassword must be at least 6 characters.' });
    }

    const studentEmail = `${registerNumber}@student.smartletter.local`;

    let studentUser;
    try {
      studentUser = await auth.getUserByEmail(studentEmail);
    } catch (err) {
      return res.status(404).json({
        error: 'No student account found for that register number.',
      });
    }

    await auth.updateUser(studentUser.uid, { password: newPassword });

    return res.json({ success: true, uid: studentUser.uid });
  } catch (err) {
    console.error('reset-student-password failed:', err);

    if (err.code === 'auth/invalid-password') {
      return res.status(400).json({ error: 'That password is invalid.' });
    }

    return res.status(500).json({ error: err.message || 'Unknown error.' });
  }
});

// ----------------------------------------------------------------
// POST /student-reset-password   (PUBLIC — no login token needed)
// Body: { "registerNumber": "...", "newPassword": "..." }
//
// Immediate, automatic self-service password reset for a student
// who forgot their password — identified by Register Number only.
// No ID card / admin approval step, by explicit request.
// ----------------------------------------------------------------
app.post('/student-reset-password', async (req, res) => {
  try {
    const registerNumber = (req.body?.registerNumber || '')
      .trim()
      .toLowerCase();
    const newPassword = req.body?.newPassword || '';

    if (!registerNumber) {
      return res.status(400).json({ error: 'registerNumber is required.' });
    }

    if (newPassword.length < 6) {
      return res
        .status(400)
        .json({ error: 'newPassword must be at least 6 characters.' });
    }

    const studentEmail = `${registerNumber}@student.smartletter.local`;

    let studentUser;
    try {
      studentUser = await auth.getUserByEmail(studentEmail);
    } catch (err) {
      return res.status(404).json({
        error: 'No student account found for that register number.',
      });
    }

    const studentDoc = await db.collection('users').doc(studentUser.uid).get();

    if (!studentDoc.exists || studentDoc.data().role !== 'student') {
      return res.status(404).json({
        error: 'No student account found for that register number.',
      });
    }

    await auth.updateUser(studentUser.uid, { password: newPassword });

    return res.json({ success: true });
  } catch (err) {
    console.error('student-reset-password failed:', err);

    if (err.code === 'auth/invalid-password') {
      return res.status(400).json({ error: 'That password is invalid.' });
    }

    return res.status(500).json({ error: err.message || 'Unknown error.' });
  }
});

// ----------------------------------------------------------------
// POST /admin-reset-password   (PUBLIC — no login token needed)
// Body: { "adminName": "...", "newPassword": "..." }
//
// Immediate, automatic self-service password reset for an admin
// who forgot their password — identified by Admin Name only.
// No verification step, by explicit request.
// ----------------------------------------------------------------
app.post('/admin-reset-password', async (req, res) => {
  try {
    const adminName = (req.body?.adminName || '').trim().toLowerCase();
    const newPassword = req.body?.newPassword || '';

    if (!adminName) {
      return res.status(400).json({ error: 'adminName is required.' });
    }

    if (newPassword.length < 6) {
      return res
        .status(400)
        .json({ error: 'newPassword must be at least 6 characters.' });
    }

    const usersSnapshot = await db
      .collection('users')
      .where('role', '==', 'admin')
      .get();

    const matches = [];
    usersSnapshot.forEach((doc) => {
      const data = doc.data();
      const storedName = (data.name || '').trim().toLowerCase();
      if (storedName === adminName) {
        matches.push({ uid: doc.id, ...data });
      }
    });

    if (matches.length === 0) {
      return res
        .status(404)
        .json({ error: 'No admin account found with that name.' });
    }

    if (matches.length > 1) {
      return res.status(409).json({
        error:
          'More than one admin account has this name. Please contact support.',
      });
    }

    await auth.updateUser(matches[0].uid, { password: newPassword });

    return res.json({ success: true });
  } catch (err) {
    console.error('admin-reset-password failed:', err);

    if (err.code === 'auth/invalid-password') {
      return res.status(400).json({ error: 'That password is invalid.' });
    }

    return res.status(500).json({ error: err.message || 'Unknown error.' });
  }
});

// ----------------------------------------------------------------
// POST /send-notification
// Header required: Authorization: Bearer <Firebase ID token>
//   (any signed-in user — student, staff, or admin)
//
// Body (send to ONE user):
//   { "targetUid": "...", "title": "...", "body": "...", "data": {...} }
//
// Body (send to SEVERAL users at once, e.g. every admin):
//   { "targetUids": ["...", "..."], "title": "...", "body": "...", "data": {...} }
//
// Looks up each target user's saved FCM tokens
// (users/{uid}.fcmTokens, an array — a user can have several
// devices) and pushes a notification to all of them. Automatically
// removes tokens that Firebase reports as no-longer-valid
// (e.g. app was uninstalled).
// ----------------------------------------------------------------
app.post('/send-notification', async (req, res) => {
  try {
    const authInfo = await requireAuth(req, res);
    if (!authInfo) return;

    const title = (req.body?.title || '').trim();
    const body = (req.body?.body || '').trim();
    const data = req.body?.data || {};

    let targetUids = [];

    if (Array.isArray(req.body?.targetUids)) {
      targetUids = req.body.targetUids.filter(
        (uid) => typeof uid === 'string' && uid.trim().length > 0,
      );
    } else if (typeof req.body?.targetUid === 'string') {
      targetUids = [req.body.targetUid];
    }

    if (targetUids.length === 0) {
      return res.status(400).json({
        error: 'targetUid or targetUids is required.',
      });
    }

    if (!title || !body) {
      return res.status(400).json({ error: 'title and body are required.' });
    }

    // Stringify all data values — FCM data payloads must be
    // string-to-string maps.
    const stringData = {};
    Object.keys(data).forEach((key) => {
      stringData[key] = String(data[key]);
    });

    // ------------------------------------------------------
    // Collect every token for every target user.
    // ------------------------------------------------------
    const tokenToUid = new Map();

    for (const uid of targetUids) {
      const userDoc = await db.collection('users').doc(uid).get();

      if (!userDoc.exists) continue;

      const tokens = userDoc.data().fcmTokens;

      if (Array.isArray(tokens)) {
        tokens.forEach((token) => {
          if (typeof token === 'string' && token.trim().length > 0) {
            tokenToUid.set(token, uid);
          }
        });
      }
    }

    const allTokens = Array.from(tokenToUid.keys());

    if (allTokens.length === 0) {
      return res.json({
        success: true,
        sent: 0,
        note: 'No registered devices for the target user(s).',
      });
    }

    // ------------------------------------------------------
    // Send. FCM caps each multicast call at 500 tokens, so
    // chunk just in case.
    // ------------------------------------------------------
    const BATCH_SIZE = 500;
    let successCount = 0;
    let failureCount = 0;
    const invalidTokens = [];

    for (let i = 0; i < allTokens.length; i += BATCH_SIZE) {
      const chunk = allTokens.slice(i, i + BATCH_SIZE);

      const response = await messaging.sendEachForMulticast({
        tokens: chunk,
        notification: { title, body },
        data: stringData,
      });

      successCount += response.successCount;
      failureCount += response.failureCount;

      response.responses.forEach((result, index) => {
        if (!result.success) {
          const errorCode = result.error?.code || '';
          if (
            errorCode === 'messaging/invalid-registration-token' ||
            errorCode === 'messaging/registration-token-not-registered'
          ) {
            invalidTokens.push(chunk[index]);
          }
        }
      });
    }

    // ------------------------------------------------------
    // Clean up dead tokens so future sends don't keep failing
    // on them.
    // ------------------------------------------------------
    if (invalidTokens.length > 0) {
      const uidsToClean = new Set(
        invalidTokens.map((token) => tokenToUid.get(token)),
      );

      for (const uid of uidsToClean) {
        const tokensForThisUid = invalidTokens.filter(
          (token) => tokenToUid.get(token) === uid,
        );

        await db
          .collection('users')
          .doc(uid)
          .update({
            fcmTokens: FieldValue.arrayRemove(...tokensForThisUid),
          })
          .catch(() => {});
      }
    }

    return res.json({
      success: true,
      sent: successCount,
      failed: failureCount,
    });
  } catch (err) {
    console.error('send-notification failed:', err);
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
