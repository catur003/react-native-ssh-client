package com.rtnsshclient;

import androidx.annotation.NonNull;
import android.util.Log;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReadableMap;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.ChannelShell;
import com.jcraft.jsch.JSchException;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.Properties;
import com.rtnsshclient.NativeRTNSshClientSpec;

public class SshClientModule extends NativeRTNSshClientSpec {

    private class SSHClient {

        Session _session;
        String _key;
        // GANTI dari BufferedReader ke InputStream MENTAH (2026-08-17,
        // debugging lanjutan) - lihat catatan panjang di readAvailableOutput()
        // di bawah soal kenapa. `volatile` ditambah di 3 field ini (jaga-jaga,
        // gak ada downside) - startShell()/writeToShell() jalan di THREAD
        // TERPISAH tiap dipanggil, field yang di-share antar thread tanpa
        // `volatile`/synchronization gak ada jaminan keliatan up-to-date.
        volatile InputStream _rawInputStream;
        volatile DataOutputStream _dataOutputStream;
        volatile OutputStream _rawOutputStream; // dipakai STRATEGY 1-3, skip DataOutputStream sama sekali
        volatile Channel _channel = null;
    }

    public static String NAME = "RTNSshClient";

    private final ReactApplicationContext reactContext;
    private static final String LOGTAG = "RNSSHClient";

    // BUG FIX (shell output tidak pernah nyampe ke JS): lihat komentar
    // panjang di readAvailableOutput() di bawah buat penjelasan lengkap.
    // Angka-angka ini nentuin seberapa lama writeToShell()/startShell()
    // "nunggu" output sebelum nyerah dan balikin apa yang udah kekumpul.
    private static final long SHELL_READ_TIMEOUT_MS = 2500; // batas atas nunggu total per panggilan
    // TOGGLE EKSPERIMEN (2026-08-19) - channel KETAHUAN masih sehat PERSIS
    // sesudah write()+flush(), tapi ~100ms kemudian (thread BACKGROUND JSch
    // sendiri, bukan thread kita) udah EOF - bereaksi ke SESUATU dari
    // write() kita, bukan pas write-nya sendiri. Ganti angka konstanta di
    // bawah buat coba pendekatan beda TANPA perlu file baru tiap kali -
    // build ulang di Android Studio (cepet sekarang), tes, kalau masih
    // gagal ganti angkanya lagi, build lagi.
    //
    // STRATEGY 0 = kondisi SEKARANG (DataOutputStream.write() biasa) - buat baseline/pembanding.
    // STRATEGY 1 = tulis LANGSUNG ke OutputStream mentah (skip DataOutputStream sama sekali).
    // STRATEGY 2 = strategy 1 + eksplisit setPty(true) (jaga-jaga default PTY kebeda di fork ini).
    // STRATEGY 3 = strategy 2 + kirim per-KARAKTER (bukan whole-array sekali nembak) - beberapa server/PTY
    //              pengen input dikirim char-by-char kayak keyboard beneran, bukan blok sekaligus.
    //gagal semua
    private static final int WRITE_STRATEGY = 3;
    // Dinaikin dari 150 ke 400 (saran dari konsep PDF Zen, poin 1) - biaya
    // murah, aman dikombinasi sama fix raw-byte-stream di atas (walau
    // penyebab UTAMA "value kosong total" kemungkinan besar bukan ini -
    // lihat penjelasan panjang, `ready()`/`available()` yang gak pernah
    // true SATU KALI PUN selama 2.5 detik itu gejala beda kelas dari
    // "kepotong di tengah jeda echo-vs-hasil"). Tetep dinaikin sebagai
    // margin keamanan buat command yang outputnya kepecah beberapa paket
    // TCP dengan jeda antar-paket lebih dari 150ms.
    private static final long IDLE_GAP_MS = 400;
    private static final long POLL_INTERVAL_MS = 30; // jeda antar cek waktu BELUM dapet data sama sekali

    Map<String, SSHClient> clientPool = new HashMap<>();

    SshClientModule(ReactApplicationContext context) {
        super(context);
        this.reactContext = context;
    }

    @Override
    @NonNull
    public String getName() {
        return NAME;
    }

    @Override
    public void connectToHostByPassword(final String host, final double port, final String username, final String passwordOrKey, final String key, final Callback callback) {
        connectToHost(host, (int) port, username, passwordOrKey, null, null, key, callback);
    }

    @Override
    public void connectToHostByKey(final String host, final double port, final String username, final String passwordOrKey, final String key, final Callback callback) {
        // BUG FIX: versi sebelumnya SELALU manggil connectToHost dengan
        // keyPairs = null di sini (komentar aslinya bahkan ngaku "simplified
        // version, may need to enhance"), padahal connectToHost baca
        // `keyPairs.getString("privateKey")` tanpa null-check - itu
        // penyebab pasti crash "ReadableMap.getString on a null object
        // reference" setiap kali connectWithKey dipanggil, apapun private
        // key-nya. Sisi JS (sshclient.ts) sekarang ngirim `passwordOrKey`
        // sebagai JSON string (`JSON.stringify({ privateKey, passphrase })`)
        // - bukan lagi `.toString()` object yang cuma menghasilkan literal
        // "[object Object]". Di sini di-parse balik pakai org.json biar
        // privateKey/passphrase-nya beneran sampai ke JSch, bukan hilang.
        String privateKey = null;
        String passphrase = null;
        try {
            JSONObject json = new JSONObject(passwordOrKey);
            if (json.has("privateKey") && !json.isNull("privateKey")) {
                privateKey = json.getString("privateKey");
            }
            if (json.has("passphrase") && !json.isNull("passphrase")) {
                passphrase = json.getString("passphrase");
            }
        } catch (Exception parseError) {
            Log.e(LOGTAG, "Gagal parse payload private key (bukan JSON valid): " + parseError.getMessage());
            callback.invoke("Payload private key tidak valid di sisi native: " + parseError.getMessage());
            return;
        }

        if (privateKey == null || privateKey.isEmpty()) {
            callback.invoke("Private key kosong setelah di-parse - cek isi field Private Key di form.");
            return;
        }

        connectToHost(host, (int) port, username, null, privateKey, passphrase, key, callback);
    }

    private void connectToHost(final String host, final Integer port, final String username, final String password, final String privateKey, final String passphrase, final String key, final Callback callback) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    JSch jsch = new JSch();

                    if (password == null) {
                        // BUG FIX: sebelumnya baca dari `keyPairs.getString(...)`
                        // (ReadableMap yang SELALU null - lihat connectToHostByKey
                        // di atas). Sekarang privateKey/passphrase udah di-parse
                        // dan divalidasi non-null SEBELUM thread ini jalan.
                        byte[] privateKeyBytes = privateKey.getBytes();
                        byte[] passphraseBytes = (passphrase != null && !passphrase.isEmpty()) ? passphrase.getBytes() : null;
                        jsch.addIdentity("default", privateKeyBytes, null, passphraseBytes);
                    }

                    Session session = jsch.getSession(username, host, port);

                    if (password != null) {
                        session.setPassword(password);
                    }

                    Properties properties = new Properties();
                    properties.setProperty("StrictHostKeyChecking", "no");
                    session.setConfig(properties);
                    session.connect();

                    if (session.isConnected()) {
                        SSHClient client = new SSHClient();
                        client._session = session;
                        client._key = key;
                        clientPool.put(key, client);

                        Log.d(LOGTAG, "Session connected");
                        callback.invoke();
                    }
                } catch (JSchException error) {
                    Log.e(LOGTAG, "Connection failed: " + error.getMessage());
                    callback.invoke(error.getMessage());
                } catch (Exception error) {
                    Log.e(LOGTAG, "Connection failed: " + error.getMessage());
                    callback.invoke(error.getMessage());
                }
            }
        }).start();
    }

    @Override
    public void execute(final String command, final String key, final Callback callback) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    SSHClient client = clientPool.get(key);
                    if (client == null) {
                        throw new Exception("client is null");
                    }
                    Session session = client._session;

                    ChannelExec channel = (ChannelExec) session.openChannel("exec");
                    channel.setCommand(command);
                    channel.connect();

                    String line, response = "";
                    InputStream in = channel.getInputStream();
                    BufferedReader reader = new BufferedReader(new InputStreamReader(in));
                    while ((line = reader.readLine()) != null) {
                        response += line + "\r\n";
                    }

                    // EKSPERIMEN (belum kebukti fix, laporan "whoami no output" gak
                    // terpecahin dari analisa statis): ganti `null` jadi `""` (empty
                    // string) buat argumen error - spec TurboModule (NativeRTNSshClient.ts)
                    // declare parameter ini non-nullable `string`, bukan `string | null`.
                    // Codegen New Architecture kadang lebih ketat soal ini dibanding
                    // bridge lama, dan pola callback 2-argumen ini (error + response)
                    // gak pernah punya referensi lain yang kebukti jalan di app ini
                    // (execute() - satu-satunya method lain yang sama polanya - gak
                    // pernah dipanggil dari mana pun). JS-side aman (`if (error)`
                    // tetap falsy buat "" sama kayak null), jadi perubahan ini
                    // gak beresiko break yang lain, cuma belum pasti ini akar masalahnya.
                    callback.invoke("", response);
                } catch (JSchException error) {
                    Log.e(LOGTAG, "Error executing command: " + error.getMessage());
                    callback.invoke(error.getMessage());
                } catch (Exception error) {
                    Log.e(LOGTAG, "Error executing command: " + error.getMessage());
                    callback.invoke(error.getMessage());
                }
            }
        }).start();
    }

    @Override
    public void startShell(final String key, final String ptyType, final Callback callback) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    SSHClient client = clientPool.get(key);
                    if (client == null) {
                        throw new Exception("client is null");
                    }
                    Session session = client._session;

                    Channel channel = session.openChannel("shell");
                    ((ChannelShell) channel).setPtyType(ptyType);
                    ((ChannelShell) channel).setPtySize(80, 24, 640, 480);
                    if (WRITE_STRATEGY >= 2) {
                        // STRATEGY 2+: eksplisit minta PTY - jaga-jaga default
                        // channel.setPty() di fork/versi JSch ini beda dari
                        // yang diasumsikan (biasanya default true buat
                        // ChannelSession, tapi belum pernah dicek eksplisit).
                        ((ChannelShell) channel).setPty(true);
                    }

                    // EKSPERIMEN #4 (2026-08-19, dikonfirmasi lewat Logcat
                    // beneran, bukan nebak lagi): trace nunjukin banner
                    // (input stream, diambil SEBELUM connect() - Eksperimen
                    // #3) SELALU berhasil dapet data, TAPI writeToShell
                    // (nulis ke output stream yang di Eksperimen #3 dipindah
                    // ke SESUDAH connect()) SELALU 0 byte balik, tanpa
                    // kecuali, walau write()/flush() gak pernah nge-throw
                    // exception ("sukses" tapi kemungkinan besar nulis ke
                    // stream yang gak nyambung ke channel asli). Eksperimen
                    // #3 misahin input(sebelum)/output(sesudah) itu DUGAAN
                    // yang belum pernah dites sendiri-sendiri - sekarang
                    // dibalikin, DUA-DUANYA diambil SEBELUM connect() (sama
                    // kayak Eksperimen #2 awal, sebelum sempat dipisah).
                    InputStream in = channel.getInputStream();
                    OutputStream out = channel.getOutputStream();
                    channel.connect();

                    client._channel = channel;
                    client._rawInputStream = in;
                    client._rawOutputStream = out;
                    client._dataOutputStream = new DataOutputStream(out);

                    // BUG FIX: versi sebelumnya di sini ada loop `while
                    // (bufferedReader.readLine() != null)` yang jalan di
                    // background thread INI SELAMANYA (readLine() blocking
                    // sampai baris baru dateng), tapi tiap baris yang kebaca
                    // cuma dibungkus jadi WritableMap yang LANGSUNG DIBUANG -
                    // gak pernah di-emit ke JS lewat event emitter APAPUN
                    // (gak ada listener/spec buat itu di NativeRTNSshClient.ts).
                    // Efeknya: output shell KETELAN TOTAL, gak pernah nyampe
                    // ke JS lewat jalur manapun. Loop itu dihapus - MOTD/banner
                    // awal (kalau ada) sekarang ditangkep di sini lewat
                    // readAvailableOutput() dan dibalikin lewat callback,
                    // konsisten sama pola writeToShell() di bawah (balikin
                    // output lewat RETURN VALUE promise, bukan event).
                    String banner = readAvailableOutput(client._rawInputStream, client._channel);
                    // Sama kayak catatan EKSPERIMEN di execute() di atas.
                    callback.invoke("", banner);

                } catch (JSchException error) {
                    Log.e(LOGTAG, "Error starting shell: " + error.getMessage());
                    callback.invoke(error.getMessage());
                } catch (IOException error) {
                    Log.e(LOGTAG, "Error starting shell: " + error.getMessage());
                    callback.invoke(error.getMessage());
                } catch (Exception error) {
                    Log.e(LOGTAG, "Error sarting shell: " + error.getMessage());
                    callback.invoke(error.getMessage());
                }
            }
        }).start();
    }

    @Override
    public void writeToShell(final String str, final String key, final Callback callback) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    SSHClient client = clientPool.get(key);
                    if (client == null) {
                        throw new Exception("client is null");
                    }
                    // DEBUG SEMENTARA: pastiin objek client & channel yang
                    // ditemu writeToShell() SAMA persis kayak yang dipakai
                    // startShell() (banner udah kebukti kerja) - kalau
                    // ternyata beda instance/channel udah closed, itu jelas
                    // akar masalahnya, bukan soal timing lagi.
                    boolean channelConnected = client._channel != null && client._channel.isConnected();
                    boolean channelClosed = client._channel != null && client._channel.isClosed();

                    String response = writeAndRead(client, str);

                    // KEMUNGKINAN #2 (banyak PTY expect carriage-return "\r"
                    // buat Enter, bukan newline "\n" - beda dari mode kanonik
                    // biasa): kalau percobaan pertama kosong total, coba SEKALI
                    // LAGI kirim "\r" polos (tanpa nulis ulang command-nya -
                    // command yang tadi mungkin udah "nyangkut" di buffer
                    // baris server, cuma butuh terminator yang bener buat
                    // dieksekusi).
                    boolean retriedWithCR = false;
                    if (response.isEmpty()) {
                        retriedWithCR = true;
                        response = writeAndRead(client, "\r");
                    }

                    // DEBUG SEMENTARA: kalau MASIH kosong juga abis retry,
                    // tempelin snapshot `available()` di BEBERAPA titik waktu
                    // (bukan cuma sekali di 100ms) - biar keliatan jelas ADA
                    // data yang numpuk telat (bukti butuh nunggu lebih lama)
                    // atau BENERAN gak ada apa-apa sama sekali sepanjang waktu
                    // (bukti soal write, bukan soal timing).
                    if (response.isEmpty()) {
                        int[] checkpointsMs = { 0, 100, 300, 600, 1000, 1500 };
                        StringBuilder trace = new StringBuilder();
                        for (int ms : checkpointsMs) {
                            try {
                                Thread.sleep(ms == 0 ? 0 : 100);
                            } catch (InterruptedException ignored) {
                                Thread.currentThread().interrupt();
                            }
                            trace.append(ms).append("ms=").append(client._rawInputStream.available()).append(' ');
                        }
                        response = String.format(
                                "[NATIVE DEBUG] wroteBytes=%d channelConnected=%b channelClosed=%b retriedWithCR=%b trace(cumulative~%dms)=[%s]",
                                str.length(), channelConnected, channelClosed, retriedWithCR, 2100, trace.toString().trim()
                        );
                    }

                    callback.invoke("", response);
                } catch (IOException error) {
                    Log.e(LOGTAG, "Error writing to shell:" + error.getMessage());
                    callback.invoke(error.getMessage());
                } catch (Exception error) {
                    Log.e(LOGTAG, "Error writing to shell:" + error.getMessage());
                    callback.invoke(error.getMessage());
                }
            }
        }).start();
    }

    /**
     * Baca SEMUA output yang lagi tersedia dari shell PTY, TANPA nge-block
     * selamanya kayak `readLine()` (yang nunggu sampai ada karakter newline -
     * prompt shell interaktif SERING gak diakhiri newline, misal `root@vps:~# `
     * nunggu input tanpa `\n` di ujungnya, jadi `readLine()` bakal nyangkut
     * nunggu newline yang gak akan pernah dateng).
     *
     * REVISI 2026-08-17 (debugging lanjutan bareng Zen): versi PERTAMA fungsi
     * ini pakai `BufferedReader.ready()` + `read()` char-per-char - TERBUKTI
     * SELALU balikin string kosong di device asli (dikonfirmasi lewat
     * instrumentasi debug di JS: `typeof=string value="" length=0`, padahal
     * SSH biasa ke server yang SAMA jalan normal - jadi bukan masalah
     * server/koneksi). Dicurigai `Reader.ready()` (yang internalnya nge-cek
     * `available() > 0` TAPI lewat lapisan decoding character InputStreamReader)
     * gak seakurat manggil `available()` LANGSUNG ke InputStream mentah dari
     * channel JSch - kemungkinan ada buffering/timing di lapisan decoding
     * char itu yang bikin `ready()` gak pernah nganggep ada data padahal
     * byte udah nyampe di level stream. Sekarang ditulis ulang kerja di level
     * BYTE MENTAH (`InputStream.available()` + `read(byte[])`), decode ke
     * String cuma SEKALI di akhir - ngilangin lapisan Reader/decoding yang
     * dicurigai jadi sumber masalah.
     *
     * Strategi baca tetap sama (polling + idle-gap heuristik), cuma level
     * operasinya beda: `in.available()` (cek non-blocking langsung ke
     * stream, bukan lewat Reader) buat tau ada byte nunggu apa nggak, baca
     * pakai `read(byte[])` (bisa berapa byte sekaligus dalam satu panggilan,
     * bukan satu-satu). Begitu berhenti dapet data, tunggu jeda pendek
     * (`IDLE_GAP_MS`) siapa tau masih ada potongan TCP lain yang segera
     * nyusul - kalau abis nunggu masih tetep kosong, dianggap output buat
     * command ini udah selesai ngalir semua. `SHELL_READ_TIMEOUT_MS` jadi
     * batas atas keras biar gak nyangkut selamanya kalau server nggak
     * pernah balikin apa-apa sama sekali.
     *
     * TRADE-OFF yang disadari: ini heuristik berbasis jeda diam, BUKAN
     * deteksi "command udah selesai" yang presisi. Command yang lama jalan
     * pun output-nya tetap bakal keliatan (curl lambat dll bakal numpuk
     * sampai timeout), tapi command yang BENERAN nyampe >2.5 detik tanpa
     * ngeprint apa-apa dulu bakal keliatan "output kepotong" - cukup buat
     * pemakaian terminal biasa, bukan buat proses long-running interaktif.
     */
    /**
     * Tulis `payload` ke shell + baca balik hasilnya - dipakai `writeToShell()`
     * buat percobaan PERTAMA (command asli) dan RETRY (kirim "\r" doang kalau
     * percobaan pertama kosong). Tulis pakai byte array eksplisit
     * (`getBytes("UTF-8")` + `write(byte[])`), BUKAN `writeBytes(String)` -
     * `writeBytes` DataOutputStream cuma nulis byte RENDAH tiap char (buang
     * bit atas), identik hasilnya buat ASCII polos tapi salah buat karakter
     * non-ASCII apapun (jarang kejadian buat command shell, tapi gak ada
     * alasan pakai method yang secara teknis kurang benar kalau alternatifnya
     * sama gampangnya).
     */
    private String writeAndRead(SSHClient client, String payload) throws IOException {
        Log.d(LOGTAG, "writeAndRead[strategy=" + WRITE_STRATEGY + "]: mulai, payload=[" + payload.replace("\n", "\\n").replace("\r", "\\r") + "] channelConnected=" + (client._channel != null && client._channel.isConnected()));

        byte[] bytes = payload.getBytes("UTF-8");
        if (WRITE_STRATEGY == 0) {
            client._dataOutputStream.write(bytes);
            client._dataOutputStream.flush();
        } else if (WRITE_STRATEGY == 3) {
            // STRATEGY 3: kirim per-KARAKTER (bukan whole-array sekali
            // nembak) + flush TIAP karakter - niru keyboard beneran, buat
            // jaga-jaga server/PTY tertentu perlakukan "satu paket besar"
            // beda dari "banyak paket kecil beruntun".
            for (byte b : bytes) {
                client._rawOutputStream.write(b);
                client._rawOutputStream.flush();
            }
        } else {
            // STRATEGY 1 & 2: skip DataOutputStream sama sekali, tulis
            // LANGSUNG ke OutputStream mentah dari channel.
            client._rawOutputStream.write(bytes);
            client._rawOutputStream.flush();
        }

        Log.d(LOGTAG, "writeAndRead: write+flush selesai, " + bytes.length + " byte terkirim, LANGSUNG SESUDAH write isConnected=" + client._channel.isConnected() + " isEOF=" + client._channel.isEOF());

        // Jeda kecil (saran konsep PDF Zen, poin 2) - kasih waktu paket TCP
        // pertama (echo dari server) beneran nyampe & "numpuk" dulu sebelum
        // readAvailableOutput() mulai ngecek `available()`.
        try {
            Thread.sleep(100);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }

        Log.d(LOGTAG, "writeAndRead: mulai readAvailableOutput, rawInputStream=" + (client._rawInputStream != null));
        String result = readAvailableOutput(client._rawInputStream, client._channel);
        Log.d(LOGTAG, "writeAndRead: hasil akhir length=" + result.length() + " isi=[" + result.replace("\n", "\\n").replace("\r", "\\r") + "]");
        return result;
    }

    private String readAvailableOutput(InputStream in, Channel channel) throws IOException {
        java.io.ByteArrayOutputStream result = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        long deadline = System.currentTimeMillis() + SHELL_READ_TIMEOUT_MS;
        boolean gotAnything = false;
        int loopCount = 0;
        boolean loggedDisconnect = false;

        Log.d(LOGTAG, "readAvailableOutput: mulai polling, in.available() awal=" + in.available() + " isConnected=" + channel.isConnected() + " isEOF=" + channel.isEOF());

        while (System.currentTimeMillis() < deadline) {
            loopCount++;

            // BARU: cek isConnected()/isEOF() TIAP iterasi (bukan cuma di
            // awal/akhir) - begitu KETAHUAN berubah jadi disconnect/EOF,
            // di-log SEKALI (loggedDisconnect flag, biar gak banjir log
            // ratusan baris sama abis kejadian sekali).
            if (!loggedDisconnect && (!channel.isConnected() || channel.isEOF())) {
                Log.d(LOGTAG, "readAvailableOutput: channel BERUBAH jadi disconnect/EOF di loop#" + loopCount + " (elapsed=" + (SHELL_READ_TIMEOUT_MS - (deadline - System.currentTimeMillis())) + "ms) isConnected=" + channel.isConnected() + " isEOF=" + channel.isEOF() + " exitStatus=" + channel.getExitStatus());
                loggedDisconnect = true;
            }

            int available = in.available();
            if (loopCount <= 5 || loopCount % 20 == 0) {
                // Log SEMUA iterasi awal (5 pertama) + tiap 20 iterasi
                // sesudahnya - biar gak banjir log ribuan baris identik
                // (POLL_INTERVAL_MS 30ms x 2500ms timeout = ratusan iterasi),
                // tapi tetep keliatan progresnya kalau lama.
                Log.d(LOGTAG, "readAvailableOutput: loop#" + loopCount + " available()=" + available + " gotAnything=" + gotAnything);
            }
            if (available > 0) {
                int n = in.read(buf, 0, Math.min(available, buf.length));
                Log.d(LOGTAG, "readAvailableOutput: baca " + n + " byte");
                if (n == -1) break; // stream ditutup dari sisi server
                if (n > 0) {
                    result.write(buf, 0, n);
                    gotAnything = true;
                }
                continue;
            }

            if (gotAnything) {
                try {
                    Thread.sleep(IDLE_GAP_MS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    break;
                }
                if (in.available() <= 0) break; // masih diam setelah jeda -> anggap selesai
            } else {
                try {
                    Thread.sleep(POLL_INTERVAL_MS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        Log.d(LOGTAG, "readAvailableOutput: SELESAI, total loop=" + loopCount + " gotAnything=" + gotAnything + " totalBytes=" + result.size() + " isConnected_akhir=" + channel.isConnected());
        return result.toString("UTF-8");
    }

    @Override
    public void closeShell(final String key) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    SSHClient client = clientPool.get(key);
                    if (client == null) {
                        throw new Exception("client is null");
                    }
                    if (client._channel != null) {
                        client._channel.disconnect();
                    }

                    if (client._dataOutputStream != null) {
                        client._dataOutputStream.flush();
                        client._dataOutputStream.close();
                    }

                    if (client._rawInputStream != null) {
                        client._rawInputStream.close();
                    }
                } catch (IOException error) {
                    Log.e(LOGTAG, "Error closing shell:" + error.getMessage());
                } catch (Exception error) {
                    Log.e(LOGTAG, "Error closing shell:" + error.getMessage());
                }
            }
        }).start();
    }

    @Override
    public void disconnect(final String key) {
        this.closeShell(key);

        SSHClient client = clientPool.get(key);
        if (client != null) {
            client._session.disconnect();
        }
    }
}