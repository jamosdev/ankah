#include "ankah/language.h"
#include "header_names.h"
#include "language_internal.h"
#include "language_names.h"

#include <stdio.h>
#include <string.h>

#define LANGUAGE_LOG_LIMIT (1024U * 1024U)

static FILE *language_log;
static size_t language_log_size;
static int language_log_capped;
static int language_log_failed;

typedef struct {
    const char *name;
    const char *text[ANKAH_LANGUAGE_COUNT];
} localized_text;

static const localized_text dashboard_text[] = {
    {"title", {"Ankah dashboard", "Ankah ダッシュボード", "Panel de Ankah"}},
    {"starting", {"Starting", "開始しています", "Iniciando"}},
    {"mask_addresses", {"Mask addresses", "アドレスを隠す", "Ocultar direcciones"}},
    {"download_metrics_csv", {"Download metrics CSV", "指標を CSV でダウンロード", "Descargar métricas CSV"}},
    {"light_theme", {"Light theme", "ライトテーマ", "Tema claro"}},
    {"dark_theme", {"Dark theme", "ダークテーマ", "Tema oscuro"}},
    {"dashboard_token", {"Dashboard token", "ダッシュボードのトークン", "Token del panel"}},
    {"enter_token", {"Enter the token from the dashboard token file.", "ダッシュボードのトークンファイルにあるトークンを入力してください。", "Introduce el token del archivo de tokens del panel."}},
    {"token", {"Token", "トークン", "Token"}},
    {"token_format", {"64 lowercase hexadecimal characters", "小文字の16進数64文字", "64 caracteres hexadecimales en minúscula"}},
    {"open_dashboard", {"Open dashboard", "ダッシュボードを開く", "Abrir el panel"}},
    {"authenticator_code", {"Authenticator code", "認証アプリのコード", "Código de autenticación"}},
    {"enter_code", {"Enter the six-digit code from your authenticator app.", "認証アプリの6桁のコードを入力してください。", "Introduce el código de seis dígitos de tu aplicación de autenticación."}},
    {"code", {"Six-digit code", "6桁のコード", "Código de seis dígitos"}},
    {"code_rejected", {"The code was not accepted. Check the code and device time.", "コードが認証されませんでした。コードと端末の時刻を確認してください。", "No se aceptó el código. Comprueba el código y la hora del dispositivo."}},
    {"too_many_codes", {"Too many attempts. Try again in a minute.", "試行回数が多すぎます。1分後に再試行してください。", "Demasiados intentos. Vuelve a intentarlo en un minuto."}},
    {"use_dashboard_token", {"Use dashboard token", "ダッシュボードのトークンを使う", "Usar token del panel"}},
    {"use_authenticator_code", {"Use authenticator code", "認証アプリのコードを使う", "Usar código de autenticación"}},
    {"setup_authenticator", {"Set up authenticator", "認証アプリを設定", "Configurar autenticación"}},
    {"scan_authenticator", {"Scan this QR code with your authenticator app. The dashboard token is needed to show it again.", "認証アプリでこのQRコードを読み取ってください。再表示にはダッシュボードのトークンが必要です。", "Escanea este código QR con tu aplicación de autenticación. Necesitarás el token del panel para verlo de nuevo."}},
    {"setup_qr_alt", {"Authenticator setup QR code", "認証アプリ設定用QRコード", "Código QR para configurar la autenticación"}},
    {"sign_out", {"Sign out", "サインアウト", "Cerrar sesión"}},
    {"close", {"Close", "閉じる", "Cerrar"}},
    {"now", {"Now", "現在", "Ahora"}},
    {"throughput_now", {"Throughput to clients now", "現在のクライアント向け転送量", "Tráfico actual hacia los clientes"}},
    {"measuring", {"Measuring", "計測中", "Midiendo"}},
    {"connections", {"Connections", "接続", "Conexiones"}},
    {"saved_post_memory", {"Saved POST memory", "保存された POST のメモリ", "Memoria de POST guardados"}},
    {"static_cache", {"Static cache", "静的ファイルのキャッシュ", "Caché de archivos estáticos"}},
    {"throttle_connections", {"Throttled downloads", "速度制限中のダウンロード", "Descargas limitadas"}},
    {"download_queue", {"Download queue", "ダウンロード待ち", "Cola de descargas"}},
    {"time_range", {"Time range", "期間", "Intervalo"}},
    {"live", {"Live", "リアルタイム", "En vivo"}},
    {"hours_24", {"24 hours", "24時間", "24 horas"}},
    {"days_7", {"7 days", "7日間", "7 días"}},
    {"days_30", {"30 days", "30日間", "30 días"}},
    {"all", {"All", "全期間", "Todo"}},
    {"summary", {"Summary", "概要", "Resumen"}},
    {"requests_per_second", {"Requests per second", "1秒あたりのリクエスト", "Solicitudes por segundo"}},
    {"challenge_pass_rate", {"Challenge pass rate", "チャレンジ成功率", "Tasa de desafíos superados"}},
    {"mean_upstream_latency", {"Mean upstream latency", "上流の平均応答時間", "Latencia media del servidor de origen"}},
    {"throttle_throughput", {"Throttled throughput", "速度制限中の転送量", "Tráfico de descargas limitadas"}},
    {"mean_queue_wait", {"Mean queue wait", "平均待ち時間", "Espera media en cola"}},
    {"throughput", {"Throughput", "転送量", "Tráfico"}},
    {"table", {"Table", "表", "Tabla"}},
    {"throughput_note", {"The gap between the lines is traffic Ankah served itself: challenge pages, its own files and packaged static files.", "2本の線の差は、Ankah 自身が配信したチャレンジページ、内部ファイル、同梱の静的ファイルの通信量です。", "La diferencia entre las líneas es el tráfico servido por Ankah: páginas de desafío, archivos propios y archivos estáticos incluidos."}},
    {"download_throttle", {"Download throttle", "ダウンロードの速度制限", "Límite de descargas"}},
    {"bytes_by_hour", {"Bytes to clients by hour", "時間ごとのクライアント向けバイト数", "Bytes por hora hacia los clientes"}},
    {"heatmap_note", {"Cells are UTC hours placed at their local start time. Hourly detail covers the last 30 days.", "各セルは現地時刻の開始位置に配置した UTC の1時間を示します。時間単位の詳細は過去30日分です。", "Cada celda representa una hora UTC situada en su hora de inicio local. El detalle por horas cubre los últimos 30 días."}},
    {"open_connections_now", {"Open connections now", "現在の接続", "Conexiones abiertas ahora"}},
    {"address", {"Address", "アドレス", "Dirección"}},
    {"state", {"State", "状態", "Estado"}},
    {"age", {"Age", "経過時間", "Antigüedad"}},
    {"in", {"In", "受信", "Entrada"}},
    {"out", {"Out", "送信", "Salida"}},
    {"reset_statistics", {"Reset statistics", "統計をリセット", "Restablecer estadísticas"}},
    {"range_live_words", {"over the last few minutes", "過去数分間", "en los últimos minutos"}},
    {"range_live_note", {"Rates between polls, last five minutes.", "過去5分間のポーリング間の速度。", "Tasas entre consultas durante los últimos cinco minutos."}},
    {"range_24h_words", {"over the last 24 hours", "過去24時間", "en las últimas 24 horas"}},
    {"range_24h_note", {"Hourly averages, last 24 hours.", "過去24時間の1時間ごとの平均。", "Medias por hora de las últimas 24 horas."}},
    {"range_7d_words", {"over the last 7 days", "過去7日間", "en los últimos 7 días"}},
    {"range_7d_note", {"Hourly averages, last 7 days.", "過去7日間の1時間ごとの平均。", "Medias por hora de los últimos 7 días."}},
    {"range_30d_words", {"over the last 30 days", "過去30日間", "en los últimos 30 días"}},
    {"range_30d_note", {"Daily averages, last 30 days.", "過去30日間の日ごとの平均。", "Medias diarias de los últimos 30 días."}},
    {"range_all_words", {"since the statistics epoch", "統計の開始以降", "desde el inicio de las estadísticas"}},
    {"range_all_note", {"Daily averages since the statistics epoch.", "統計の開始以降の日ごとの平均。", "Medias diarias desde el inicio de las estadísticas."}},
    {"reading_request", {"Reading request", "リクエストを読み込み中", "Leyendo solicitud"}},
    {"responding", {"Responding", "応答中", "Respondiendo"}},
    {"sending_file", {"Sending file", "ファイルを送信中", "Enviando archivo"}},
    {"receiving_body", {"Receiving body", "本文を受信中", "Recibiendo cuerpo"}},
    {"connecting_upstream", {"Connecting upstream", "上流に接続中", "Conectando con el servidor de origen"}},
    {"forwarding", {"Forwarding", "転送中", "Reenviando"}},
    {"websocket_tunnel", {"WebSocket tunnel", "WebSocket トンネル", "Túnel WebSocket"}},
    {"waiting_token", {"Waiting for a token", "トークンを待っています", "Esperando un token"}},
    {"token_rejected", {"The token was not accepted. Check the dashboard token file.", "トークンが認証されませんでした。ダッシュボードのトークンファイルを確認してください。", "No se aceptó el token. Comprueba el archivo de tokens del panel."}},
    {"connection_lost", {"Connection lost, retrying", "接続が切れました。再試行しています", "Conexión perdida; reintentando"}},
    {"paused", {"Paused while this tab is hidden", "このタブが非表示のため一時停止中", "En pausa mientras esta pestaña está oculta"}},
    {"live_updated", {"Live, updated {0}", "リアルタイム、{0} に更新", "En vivo, actualizado a las {0}"}},
    {"connecting", {"Connecting", "接続中", "Conectando"}},
    {"so_far", {", so far", "（現在まで）", ", hasta ahora"}},
    {"range_between", {"{0} to {1}", "{0} から {1}", "de {0} a {1}"}},
    {"average_before", {"Average before {0}", "{0} より前の平均", "Media anterior a {0}"}},
    {"peak_before", {"Peak before {0}", "{0} より前のピーク", "Pico anterior a {0}"}},
    {"statistics_since", {"Statistics since {0}, {1} ago.", "統計開始: {0}（{1} 前）。", "Estadísticas desde {0}, hace {1}."}},
    {"served_itself", {"{0} served by Ankah itself {1}", "Ankah 自身が {1} に配信した割合: {0}", "{0} servido directamente por Ankah {1}"}},
    {"nothing_sent", {"Nothing sent to clients {0}", "クライアントへの送信なし（{0}）", "No se enviaron datos a los clientes {0}"}},
    {"of", {"{0} of {1}", "{0} / {1}", "{0} de {1}"}},
    {"disabled", {"Disabled", "無効", "Desactivado"}},
    {"at_limit", {"At or near the limit", "上限に達したか、近づいています", "En el límite o cerca de él"}},
    {"approaching_limit", {"Approaching the limit", "上限に近づいています", "Acercándose al límite"}},
    {"tls_open", {"{0} TLS sockets open", "開いている TLS ソケット: {0}", "{0} conexiones TLS abiertas"}},
    {"saved_sessions", {"{0} saved, {1} challenge sessions", "保存済み: {0}、チャレンジセッション: {1}", "{0} guardados, {1} sesiones de desafío"}},
    {"no_waits", {"No queued downloads", "待機中のダウンロードなし", "No hay descargas en cola"}},
    {"active_downloads", {"Active downloads", "実行中のダウンロード", "Descargas activas"}},
    {"queued_downloads", {"Queued downloads", "待機中のダウンロード", "Descargas en cola"}},
    {"throttle_capacity_label", {"Active and queued throttled downloads", "実行中と待機中の速度制限対象ダウンロード", "Descargas limitadas activas y en cola"}},
    {"active", {"Active", "実行中", "Activo"}},
    {"queued", {"Queued", "待機中", "En cola"}},
    {"peak_active", {"Peak active", "実行中の最大数", "Máximo de activas"}},
    {"peak_queued", {"Peak queued", "待機中の最大数", "Máximo en cola"}},
    {"peak_connections", {"Peak connections", "最大接続数", "Máximo de conexiones"}},
    {"none_issued", {"None issued", "発行なし", "Ninguno emitido"}},
    {"no_responses", {"No responses", "応答なし", "Sin respuestas"}},
    {"not_enough_data", {"Not enough data yet. Points appear as polls and buckets complete.", "まだ十分なデータがありません。ポーリングと集計期間が完了すると点が表示されます。", "Aún no hay suficientes datos. Los puntos aparecerán cuando se completen las consultas y los intervalos."}},
    {"no_data", {"No data", "データなし", "Sin datos"}},
    {"to_clients", {"To clients", "クライアントへ", "A los clientes"}},
    {"to_clients_lower", {"to clients", "クライアントへ", "a los clientes"}},
    {"from_application", {"From the application", "アプリケーションから", "Desde la aplicación"}},
    {"from_application_lower", {"from the application", "アプリケーションから", "desde la aplicación"}},
    {"average_before_history", {"Average before daily history", "日別履歴より前の平均", "Media anterior al historial diario"}},
    {"throughput_label", {"Throughput to clients and from the application", "クライアント向けとアプリケーションからの転送量", "Tráfico hacia los clientes y desde la aplicación"}},
    {"time", {"Time", "時刻", "Hora"}},
    {"peak_before_history", {"Peak before daily history", "日別履歴より前のピーク", "Pico anterior al historial diario"}},
    {"open_connections", {"Open connections", "開いている接続", "Conexiones abiertas"}},
    {"peak_connections_period", {"Peak connections per period", "期間ごとの最大接続数", "Máximo de conexiones por intervalo"}},
    {"open", {"Open", "開いている数", "Abiertas"}},
    {"peak", {"Peak", "ピーク", "Pico"}},
    {"hour_starting", {"Hour starting", "開始時刻", "Hora de inicio"}},
    {"bytes_to_clients", {"Bytes to clients", "クライアント向けバイト数", "Bytes hacia los clientes"}},
    {"no_hourly_data", {"No hourly data yet.", "時間単位のデータはまだありません。", "Aún no hay datos por hora."}},
    {"heatmap_label", {"Bytes sent to clients in each hour, by day", "日別・時間別のクライアント向け送信バイト数", "Bytes enviados a los clientes por hora y día"}},
    {"no_open_connections", {"No open connections", "開いている接続はありません", "No hay conexiones abiertas"}},
    {"more_connections", {"{0} more open connections moved {1} in and {2} out.", "ほかの接続 {0} 件の受信量 {1}、送信量 {2}。", "Otras {0} conexiones abiertas movieron {1} de entrada y {2} de salida."}},
    {"confirm_reset", {"Confirm reset", "リセットを確認", "Confirmar restablecimiento"}},
    {"persistence_failed", {"Statistics were reset in memory, but the snapshot could not be updated. Older data may return after a restart.", "統計はメモリ上でリセットされましたが、スナップショットを更新できませんでした。再起動後に古いデータが戻る可能性があります。", "Las estadísticas se restablecieron en memoria, pero no se pudo actualizar la instantánea. Los datos anteriores podrían reaparecer tras reiniciar."}},
    {"token_invalid", {"The token is 64 lowercase hexadecimal characters.", "トークンは小文字の16進数64文字です。", "El token debe tener 64 caracteres hexadecimales en minúscula."}},
    {"age_seconds", {"{0}s", "{0}秒", "{0} s"}},
    {"age_minutes", {"{0}m {1}s", "{0}分{1}秒", "{0} min {1} s"}},
    {"age_hours", {"{0}h {1}m", "{0}時間{1}分", "{0} h {1} min"}},
    {"age_days", {"{0}d {1}h", "{0}日{1}時間", "{0} d {1} h"}},
    {"challenge_progress", {"{0} guesses · {1}/s · {2}% chance of success by now", "試行 {0} 回 · 毎秒 {1} 回 · 現時点の成功確率 {2}%", "{0} intentos · {1}/s · {2}% de probabilidad de éxito hasta ahora"}},
    {"challenge_browser_unsupported", {"This browser cannot solve the challenge", "このブラウザーではチャレンジを解けません", "Este navegador no puede resolver el desafío"}},
    {"challenge_search_exhausted", {"Challenge search exhausted", "チャレンジの探索範囲を使い切りました", "Se agotó la búsqueda del desafío"}},
    {"challenge_worker_failed", {"Solver worker failed", "計算ワーカーが失敗しました", "Falló el proceso de resolución"}},
    {"challenge_startup_timeout", {"Solver startup timed out", "計算ワーカーの起動がタイムアウトしました", "Se agotó el tiempo para iniciar el proceso de resolución"}},
    {"challenge_invalid", {"Invalid challenge", "チャレンジが無効です", "El desafío no es válido"}},
    {"challenge_passed_continuing", {"Challenge passed. Continuing...", "チャレンジに成功しました。続行しています...", "Desafío superado. Continuando..."}},
    {"challenge_passed_mobile", {"Challenge passed. Click Finished on the original page.", "チャレンジに成功しました。元のページで「完了」をクリックしてください。", "Desafío superado. Haz clic en Finalizar en la página original."}},
    {"challenge_answer_rejected", {"The answer was rejected", "回答が拒否されました", "Se rechazó la respuesta"}},
    {"challenge_failed", {"Could not complete the challenge. Please retry.", "チャレンジを完了できませんでした。再試行してください。", "No se pudo completar el desafío. Vuelve a intentarlo."}},
    {"challenge_solver_unavailable", {"Solver unavailable", "計算プログラムを利用できません", "El programa de resolución no está disponible"}},
    {"challenge_invalid_solver", {"Invalid solver", "計算プログラムが無効です", "El programa de resolución no es válido"}},
    {"challenge_invalid_solver_memory", {"Invalid solver memory", "計算プログラムのメモリが無効です", "La memoria del programa de resolución no es válida"}},
    {"challenge_solver_range_exhausted", {"Solver range exhausted", "計算プログラムの探索範囲を使い切りました", "Se agotó el intervalo de búsqueda"}}
};

typedef struct {
    const char *english;
    const char *translated[ANKAH_LANGUAGE_COUNT];
} translated_message;

static const translated_message message_text[] = {
    {"Request body timed out\n", {"Request body timed out\n", "リクエスト本文の受信がタイムアウトしました\n", "Se agotó el tiempo para recibir el cuerpo de la solicitud\n"}},
    {"Unknown asset\n", {"Unknown asset\n", "不明なアセットです\n", "Recurso desconocido\n"}},
    {"Method not allowed\n", {"Method not allowed\n", "このメソッドは使用できません\n", "Método no permitido\n"}},
    {"Use GET or HEAD\n", {"Use GET or HEAD\n", "GET または HEAD を使用してください\n", "Usa GET o HEAD\n"}},
    {"Request headers too large\n", {"Request headers too large\n", "リクエストヘッダーが大きすぎます\n", "Las cabeceras de la solicitud son demasiado grandes\n"}},
    {"Continuing\n", {"Continuing\n", "続行します\n", "Continuando\n"}},
    {"No acceptable static representation\n", {"No acceptable static representation\n", "利用可能な静的ファイル形式がありません\n", "No hay una representación estática aceptable\n"}},
    {"Unknown static file\n", {"Unknown static file\n", "不明な静的ファイルです\n", "Archivo estático desconocido\n"}},
    {"Service shutting down\n", {"Service shutting down\n", "サービスを停止しています\n", "El servicio se está cerrando\n"}},
    {"Crawler concurrency exceeded\n", {"Crawler concurrency exceeded\n", "クローラーの同時実行上限を超えました\n", "Se superó el límite de rastreadores simultáneos\n"}},
    {"Crawler verification unavailable\n", {"Crawler verification unavailable\n", "クローラーの検証を利用できません\n", "La verificación del rastreador no está disponible\n"}},
    {"Challenge unavailable\n", {"Challenge unavailable\n", "チャレンジを利用できません\n", "El desafío no está disponible\n"}},
    {"Challenge capacity reached\n", {"Challenge capacity reached\n", "チャレンジの容量上限に達しました\n", "Se alcanzó la capacidad de desafíos\n"}},
    {"Invalid return path\n", {"Invalid return path\n", "戻り先のパスが無効です\n", "La ruta de retorno no es válida\n"}},
    {"Unknown code\n", {"Unknown code\n", "不明なコードです\n", "Código desconocido\n"}},
    {"Challenge expired\n", {"Challenge expired\n", "チャレンジの有効期限が切れました\n", "El desafío ha caducado\n"}},
    {"Invalid answer\n", {"Invalid answer\n", "回答が無効です\n", "La respuesta no es válida\n"}},
    {"Challenge passed. Click Finished on the original page.\n", {"Challenge passed. Click Finished on the original page.\n", "チャレンジに成功しました。元のページで「完了」をクリックしてください。\n", "Desafío superado. Haz clic en Finalizar en la página original.\n"}},
    {"Challenge not passed\n", {"Challenge not passed\n", "チャレンジに成功していません\n", "El desafío no se ha superado\n"}},
    {"Invalid challenge\n", {"Invalid challenge\n", "チャレンジが無効です\n", "El desafío no es válido\n"}},
    {"Invalid challenge answer\n", {"Invalid challenge answer\n", "チャレンジの回答が無効です\n", "La respuesta al desafío no es válida\n"}},
    {"Challenge passed. Retry your request.\n", {"Challenge passed. Retry your request.\n", "チャレンジに成功しました。リクエストを再試行してください。\n", "Desafío superado. Vuelve a intentar la solicitud.\n"}},
    {"Unknown Ankah endpoint\n", {"Unknown Ankah endpoint\n", "不明な Ankah エンドポイントです\n", "Punto de acceso de Ankah desconocido\n"}},
    {"Upstream unavailable\n", {"Upstream unavailable\n", "上流サーバーを利用できません\n", "El servidor de origen no está disponible\n"}},
    {"Invalid continuation\n", {"Invalid continuation\n", "続行情報が無効です\n", "La continuación no es válida\n"}},
    {"Continuation expired\n", {"Continuation expired\n", "続行情報の有効期限が切れました\n", "La continuación ha caducado\n"}},
    {"Dashboard requests carry no body\n", {"Dashboard requests carry no body\n", "ダッシュボードへのリクエストに本文は指定できません\n", "Las solicitudes al panel no pueden tener cuerpo\n"}},
    {"Unknown dashboard path\n", {"Unknown dashboard path\n", "不明なダッシュボードのパスです\n", "Ruta del panel desconocida\n"}},
    {"Use GET\n", {"Use GET\n", "GET を使用してください\n", "Usa GET\n"}},
    {"Dashboard token required\n", {"Dashboard token required\n", "ダッシュボードのトークンが必要です\n", "Se requiere el token del panel\n"}},
    {"Unknown statistics path\n", {"Unknown statistics path\n", "不明な統計情報のパスです\n", "Ruta de estadísticas desconocida\n"}},
    {"Use POST\n", {"Use POST\n", "POST を使用してください\n", "Usa POST\n"}},
    {"Statistics unavailable\n", {"Statistics unavailable\n", "統計情報を利用できません\n", "Las estadísticas no están disponibles\n"}},
    {"Invalid history range\n", {"Invalid history range\n", "履歴の期間が無効です\n", "El intervalo del historial no es válido\n"}},
    {"Invalid HTTP request\n", {"Invalid HTTP request\n", "HTTP リクエストが無効です\n", "La solicitud HTTP no es válida\n"}},
    {"Invalid forwarding information\n", {"Invalid forwarding information\n", "転送情報が無効です\n", "La información de reenvío no es válida\n"}},
    {"Invalid admission information\n", {"Invalid admission information\n", "受け入れ情報が無効です\n", "La información de admisión no es válida\n"}},
    {"Anonymous connection capacity reached\n", {"Anonymous connection capacity reached\n", "匿名接続の上限に達しました\n", "Se alcanzó el límite de conexiones anónimas\n"}},
    {"Rate limit exceeded\n", {"Rate limit exceeded\n", "リクエストの速度制限を超えました\n", "Se superó el límite de solicitudes\n"}},
    {"Unsupported expectation\n", {"Unsupported expectation\n", "指定された Expect ヘッダーには対応していません\n", "La expectativa indicada no es compatible\n"}},
    {"Unsupported request body\n", {"Unsupported request body\n", "リクエスト本文には対応していません\n", "El cuerpo de la solicitud no es compatible\n"}},
    {"Chunked request body is not supported for this route\n", {"Chunked request body is not supported for this route\n", "このルートでは分割転送のリクエスト本文に対応していません\n", "Esta ruta no admite cuerpos de solicitud fragmentados\n"}},
    {"Request body too large\n", {"Request body too large\n", "リクエスト本文が大きすぎます\n", "El cuerpo de la solicitud es demasiado grande\n"}},
    {"Invalid chunked request body\n", {"Invalid chunked request body\n", "分割転送のリクエスト本文が無効です\n", "El cuerpo fragmentado de la solicitud no es válido\n"}},
    {"Invalid body size\n", {"Invalid body size\n", "本文のサイズが無効です\n", "El tamaño del cuerpo no es válido\n"}},
    {"Dashboard moved\n", {"Dashboard moved\n", "ダッシュボードの移動先を参照してください\n", "El panel se ha trasladado\n"}},
    {"Invalid HTTP/2 request\n", {"Invalid HTTP/2 request\n", "HTTP/2 リクエストが無効です\n", "La solicitud HTTP/2 no es válida\n"}},
    {"Invalid HTTP/2 request body length\n", {"Invalid HTTP/2 request body length\n", "HTTP/2 リクエスト本文の長さが無効です\n", "La longitud del cuerpo HTTP/2 no es válida\n"}},
    {"Invalid upstream response\n", {"Invalid upstream response\n", "上流サーバーの応答が無効です\n", "La respuesta del servidor de origen no es válida\n"}},
    {"Incomplete upstream response\n", {"Incomplete upstream response\n", "上流サーバーの応答が不完全です\n", "La respuesta del servidor de origen está incompleta\n"}},
    {"Upstream write failed\n", {"Upstream write failed\n", "上流サーバーへの送信に失敗しました\n", "No se pudo enviar al servidor de origen\n"}},
    {"Unexpected Host\n", {"Unexpected Host\n", "想定外の Host です\n", "El host no es el esperado\n"}},
    {"Unavailable\n", {"Unavailable\n", "利用できません\n", "No disponible\n"}},
    {"Request body queue unavailable\n", {"Request body queue unavailable\n", "リクエスト本文の待機領域を利用できません\n", "La cola de cuerpos de solicitud no está disponible\n"}},
    {"Request body buffer unavailable\n", {"Request body buffer unavailable\n", "リクエスト本文のバッファを利用できません\n", "El búfer del cuerpo de la solicitud no está disponible\n"}},
    {"Unlock, then retry this method.", {"Unlock, then retry this method.", "ロックを解除してから、このメソッドを再試行してください。", "Desbloquea el acceso y vuelve a intentar este método."}},
    {"Unlock, then retry this upload.", {"Unlock, then retry this upload.", "ロックを解除してから、このアップロードを再試行してください。", "Desbloquea el acceso y vuelve a intentar esta carga."}},
    {"Unlock, then retry this request.", {"Unlock, then retry this request.", "ロックを解除してから、リクエストを再試行してください。", "Desbloquea el acceso y vuelve a intentar la solicitud."}},
    {"Unlock required", {"Unlock required", "ロック解除が必要です", "Se requiere desbloquear"}},
    {"Unlock", {"Unlock", "ロック解除", "Desbloquear"}},
    {"Checking your browser", {"Checking your browser", "ブラウザーを確認しています", "Comprobando el navegador"}},
    {"Solving a short proof of work.", {"Solving a short proof of work.", "短い計算チャレンジを解いています。", "Resolviendo una breve prueba de trabajo."}},
    {"Starting challenge...", {"Starting challenge...", "チャレンジを開始しています...", "Iniciando el desafío..."}},
    {"Don't have JavaScript? Scan here.", {"Don't have JavaScript? Scan here.", "JavaScript を利用できない場合は、ここをスキャンしてください。", "¿No tienes JavaScript? Escanea aquí."}},
    {"Phone scanning a code", {"Phone scanning a code", "コードを読み取るスマートフォン", "Teléfono escaneando un código"}},
    {"QR code to solve on your phone", {"QR code to solve on your phone", "スマートフォンで解くための QR コード", "Código QR para resolverlo en el teléfono"}},
    {"After solving on your phone, click Finished here.", {"After solving on your phone, click Finished here.", "スマートフォンで解いた後、ここで「完了」をクリックしてください。", "Después de resolverlo en el teléfono, haz clic aquí en Finalizar."}},
    {"Finished", {"Finished", "完了", "Finalizar"}},
    {"Solve challenge", {"Solve challenge", "チャレンジを解く", "Resolver el desafío"}},
    {"Starting...", {"Starting...", "開始しています...", "Iniciando..."}},
    {"When complete, click Finished on the original page.", {"When complete, click Finished on the original page.", "完了したら、元のページで「完了」をクリックしてください。", "Al terminar, haz clic en Finalizar en la página original."}},
    {"Challenge passed. Click Finished on the original page.", {"Challenge passed. Click Finished on the original page.", "チャレンジに成功しました。元のページで「完了」をクリックしてください。", "Desafío superado. Haz clic en Finalizar en la página original."}},
    {"Download queue full", {"Download queue full", "ダウンロード待ちの上限に達しました", "La cola de descargas está llena"}},
    {"The bounded queue is full. Retrying in one second.", {"The bounded queue is full. Retrying in one second.", "待機列が満杯です。1秒後に再試行します。", "La cola está llena. Se volverá a intentar en un segundo."}},
    {"Download queued", {"Download queued", "ダウンロード待ちです", "Descarga en cola"}},
    {"Retrying in one second.", {"Retrying in one second.", "1秒後に再試行します。", "Se volverá a intentar en un segundo."}},
    {"Retry now", {"Retry now", "今すぐ再試行", "Reintentar ahora"}},
    {"Your position is %u of %u.", {"Your position is %u of %u.", "現在の順番: %u / %u。", "Tu posición es %u de %u."}},
    {"Ankah challenge required.\n", {"Ankah challenge required.\n", "Ankah のチャレンジが必要です。\n", "Se requiere un desafío de Ankah.\n"}},
    {"Unlock: ", {"Unlock: ", "ロック解除: ", "Desbloquear: "}}
};

const char *ankah_language_message(ankah_language language, const char *english) {
    size_t i;
    if (!english) return NULL;
    if (language < 0 || language >= ANKAH_LANGUAGE_COUNT) language = ANKAH_LANGUAGE_EN;
    for (i = 0; i < sizeof(message_text) / sizeof(message_text[0]); ++i)
        if (strcmp(english, message_text[i].english) == 0)
            return message_text[i].translated[language];
    return english;
}

typedef struct {
    char range[ANKAH_MAX_VALUE];
    size_t length;
    int quality;
    int wildcard;
} language_range;

static int ascii_equal(const char *left, size_t size, const char *right) {
    size_t i;
    if (strlen(right) != size) return 0;
    for (i = 0; i < size; ++i) {
        unsigned char a = (unsigned char)left[i];
        unsigned char b = (unsigned char)right[i];
        if (a >= 'A' && a <= 'Z') a = (unsigned char)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (unsigned char)(b + 32);
        if (a != b) return 0;
    }
    return 1;
}

static int quality_value(const char *text, size_t size, int *out) {
    size_t i = 0, digits = 0;
    int whole, fraction = 0;
    if (!size || (text[0] != '0' && text[0] != '1')) return -1;
    whole = text[i++] - '0';
    if (i < size) {
        if (text[i++] != '.') return -1;
        while (i < size) {
            if (text[i] < '0' || text[i] > '9' || ++digits > 3) return -1;
            fraction = fraction * 10 + text[i++] - '0';
        }
    }
    if (whole && fraction) return -1;
    while (digits++ < 3) fraction *= 10;
    *out = whole ? 1000 : fraction;
    return 0;
}

static int parse_range(const char *start, const char *end, language_range *out) {
    const char *semicolon, *range_end, *parameter;
    size_t i, subtag = 0;
    int first_subtag = 1;
    while (start < end && (*start == ' ' || *start == '\t')) ++start;
    while (end > start && (end[-1] == ' ' || end[-1] == '\t')) --end;
    if (start == end) return -1;
    semicolon = memchr(start, ';', (size_t)(end - start));
    range_end = semicolon ? semicolon : end;
    while (range_end > start && (range_end[-1] == ' ' || range_end[-1] == '\t')) --range_end;
    if (range_end == start || (size_t)(range_end - start) >= sizeof(out->range)) return -1;
    out->wildcard = range_end - start == 1 && *start == '*';
    if (!out->wildcard) {
        for (i = 0; i < (size_t)(range_end - start); ++i) {
            unsigned char c = (unsigned char)start[i];
            int alpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
            int digit = c >= '0' && c <= '9';
            if (c == '-') {
                if (!subtag || subtag > 8) return -1;
                subtag = 0;
                first_subtag = 0;
            } else {
                if ((first_subtag && !alpha) ||
                    (!first_subtag && !alpha && !digit) || ++subtag > 8) return -1;
            }
        }
        if (!subtag || subtag > 8) return -1;
    }
    out->length = (size_t)(range_end - start);
    for (i = 0; i < out->length; ++i) {
        unsigned char c = (unsigned char)start[i];
        out->range[i] = (char)(c >= 'A' && c <= 'Z' ? c + 32 : c);
    }
    out->range[out->length] = 0;
    out->quality = 1000;
    if (!semicolon) return 0;
    parameter = semicolon + 1;
    while (parameter < end && (*parameter == ' ' || *parameter == '\t')) ++parameter;
    if (end - parameter < 2 || !ascii_equal(parameter, 1, "q") || parameter[1] != '=')
        return -1;
    parameter += 2;
    while (end > parameter && (end[-1] == ' ' || end[-1] == '\t')) --end;
    return quality_value(parameter, (size_t)(end - parameter), &out->quality);
}

static const struct ankah_language_keyword *match_range(char *range, size_t length) {
    const struct ankah_language_keyword *keyword;
    size_t current = length;
    while (current) {
        keyword = ankah_language_lookup(range, current);
        if (keyword) return keyword;
        while (current && range[current - 1] != '-') --current;
        if (current) --current;
    }
    return NULL;
}

ankah_language ankah_language_select(const ankah_request *request) {
    ankah_language selected = ANKAH_LANGUAGE_EN;
    int best = -1;
    unsigned int i;
    if (!request) return selected;
    for (i = 0; i < request->count; ++i) {
        const char *p, *end;
        if (!ankah_header_is(&request->headers[i], ANKAH_HEADER_ACCEPT_LANGUAGE)) continue;
        p = request->headers[i].value;
        do {
            language_range range;
            const struct ankah_language_keyword *keyword;
            end = strchr(p, ',');
            if (!end) end = p + strlen(p);
            if (parse_range(p, end, &range) == 0 && range.quality > 0) {
                keyword = range.wildcard ? ankah_language_lookup("en", 2) :
                                           match_range(range.range, range.length);
                if (keyword && range.quality > best) {
                    selected = keyword->language;
                    best = range.quality;
                }
            }
            p = *end ? end + 1 : end;
        } while (*end);
    }
    return selected;
}

const char *ankah_language_tag(ankah_language language) {
    static const char *const tags[ANKAH_LANGUAGE_COUNT] = {"en", "ja", "es"};
    return language >= 0 && language < ANKAH_LANGUAGE_COUNT ? tags[language] : "en";
}

const char *ankah_language_text(ankah_language language, const char *name) {
    size_t i;
    if (!name) return NULL;
    if (strcmp(name, "language_tag") == 0) return ankah_language_tag(language);
    if (language < 0 || language >= ANKAH_LANGUAGE_COUNT) language = ANKAH_LANGUAGE_EN;
    for (i = 0; i < sizeof(dashboard_text) / sizeof(dashboard_text[0]); ++i)
        if (strcmp(name, dashboard_text[i].name) == 0) return dashboard_text[i].text[language];
    return NULL;
}

static int append_bytes(unsigned char *output, size_t capacity, size_t *used,
                        const unsigned char *text, size_t amount) {
    if (amount > capacity - *used) return -1;
    if (output) memcpy(output + *used, text, amount);
    *used += amount;
    return 0;
}

static int append_html(unsigned char *output, size_t capacity, size_t *used,
                       const char *text) {
    while (*text) {
        const char *replacement = NULL;
        size_t amount;
        if (*text == '&') replacement = "&amp;";
        else if (*text == '<') replacement = "&lt;";
        else if (*text == '>') replacement = "&gt;";
        else if (*text == '"') replacement = "&quot;";
        else if (*text == '\'') replacement = "&#39;";
        amount = replacement ? strlen(replacement) : 1;
        if (append_bytes(output, capacity, used,
                (const unsigned char *)(replacement ? replacement : text), amount) != 0)
            return -1;
        ++text;
    }
    return 0;
}

int ankah_language_render_html(ankah_language language, const unsigned char *input,
                               size_t input_size, unsigned char *output,
                               size_t output_size, size_t *written,
                               ankah_language_text_lookup lookup) {
    static const char prefix[] = "<!--#echo var=\"";
    static const char suffix[] = "\" -->";
    size_t at = 0, used = 0;
    if (!input || !written || !lookup) return -1;
    while (at < input_size) {
        const unsigned char *start = memchr(input + at, '<', input_size - at);
        size_t plain = start ? (size_t)(start - input) : input_size;
        if (plain > at) {
            size_t amount = plain - at;
            if (append_bytes(output, output_size, &used, input + at, amount) != 0)
                return -1;
            at = plain;
        }
        if (!start) break;
        if (input_size - at >= 5 && memcmp(input + at, "<!--#", 5) == 0) {
            const unsigned char *name, *end;
            char key[64];
            const char *value;
            size_t key_size;
            if (input_size - at < sizeof(prefix) - 1 ||
                memcmp(input + at, prefix, sizeof(prefix) - 1) != 0) return -1;
            name = input + at + sizeof(prefix) - 1;
            end = memchr(name, '"', input_size - (size_t)(name - input));
            if (!end || input_size - (size_t)(end - input) < sizeof(suffix) - 1 ||
                memcmp(end, suffix, sizeof(suffix) - 1) != 0) return -1;
            key_size = (size_t)(end - name);
            if (!key_size || key_size >= sizeof(key)) return -1;
            memcpy(key, name, key_size);
            key[key_size] = 0;
            value = lookup(language, key);
            if (!value || append_html(output, output_size, &used, value) != 0) return -1;
            at = (size_t)(end - input) + sizeof(suffix) - 1;
        } else {
            if (append_bytes(output, output_size, &used, input + at, 1) != 0) return -1;
            ++at;
        }
    }
    *written = used;
    return 0;
}

int ankah_language_log_open(const char *path) {
    long size;
    if (!path || !*path || language_log) return -1;
    language_log = fopen(path, "a+b");
    if (!language_log || fseek(language_log, 0, SEEK_END) != 0 ||
        (size = ftell(language_log)) < 0) {
        if (language_log) fclose(language_log);
        language_log = NULL;
        return -1;
    }
    language_log_size = (size_t)size;
    return 0;
}

static void log_unknown(const language_range *range) {
    size_t amount = range->length + 1;
    if (!language_log || language_log_failed) return;
    if (language_log_size >= LANGUAGE_LOG_LIMIT ||
        amount > LANGUAGE_LOG_LIMIT - language_log_size) {
        if (!language_log_capped) {
            fprintf(stderr, "Ankah unknown-language log reached its 1 MiB limit\n");
            language_log_capped = 1;
        }
        return;
    }
    if (fwrite(range->range, 1, range->length, language_log) != range->length ||
        fputc('\n', language_log) == EOF) {
        fprintf(stderr, "Ankah unknown-language log write failed\n");
        language_log_failed = 1;
        return;
    }
    language_log_size += amount;
}

void ankah_language_log_request(const ankah_request *request) {
    unsigned int i;
    int wrote = 0;
    if (!language_log || !request) return;
    for (i = 0; i < request->count; ++i) {
        const char *p, *end;
        if (!ankah_header_is(&request->headers[i], ANKAH_HEADER_ACCEPT_LANGUAGE)) continue;
        p = request->headers[i].value;
        do {
            language_range range;
            end = strchr(p, ',');
            if (!end) end = p + strlen(p);
            if (parse_range(p, end, &range) == 0 && range.quality > 0 && !range.wildcard &&
                !match_range(range.range, range.length)) {
                log_unknown(&range);
                wrote = 1;
            }
            p = *end ? end + 1 : end;
        } while (*end);
    }
    if (wrote && !language_log_failed && fflush(language_log) != 0) {
        fprintf(stderr, "Ankah unknown-language log flush failed\n");
        language_log_failed = 1;
    }
}

void ankah_language_log_close(void) {
    if (language_log) fclose(language_log);
    language_log = NULL;
    language_log_size = 0;
    language_log_capped = 0;
    language_log_failed = 0;
}
