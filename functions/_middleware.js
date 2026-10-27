// Cloudflare Pages Functions: サイト全体にBasic認証をかけるミドルウェア
//
// 認証情報はコードに書かず、Cloudflare PagesのEnvironment Variablesから読み込む。
//   BASIC_AUTH_USERNAME : ユーザー名
//   BASIC_AUTH_PASSWORD : パスワード(Secretとして登録すること)
//
// 設定方法: Cloudflareダッシュボード > Workers & Pages > 対象プロジェクト
//   > Settings > Environment variables で、Production(必要ならPreviewも)に追加する。

export async function onRequest(context) {
  const { request, env, next } = context;

  const expectedUser = env.BASIC_AUTH_USERNAME;
  const expectedPass = env.BASIC_AUTH_PASSWORD;

  // 環境変数が設定されていない場合は、認証をスキップせず設定ミスとして扱う
  if (!expectedUser || !expectedPass) {
    return new Response(
      "Basic認証の環境変数(BASIC_AUTH_USERNAME / BASIC_AUTH_PASSWORD)が設定されていません。",
      { status: 500 }
    );
  }

  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Basic ")) {
    return unauthorized();
  }

  let decoded;
  try {
    decoded = atob(authHeader.slice("Basic ".length).trim());
  } catch (e) {
    return unauthorized();
  }

  const separatorIndex = decoded.indexOf(":");
  if (separatorIndex === -1) {
    return unauthorized();
  }

  const inputUser = decoded.slice(0, separatorIndex);
  const inputPass = decoded.slice(separatorIndex + 1);

  const ok =
    timingSafeEqual(inputUser, expectedUser) &&
    timingSafeEqual(inputPass, expectedPass);

  if (!ok) {
    return unauthorized();
  }

  return next();
}

function unauthorized() {
  return new Response("認証が必要です。", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Kintai App", charset="UTF-8"',
    },
  });
}

// 文字列長や内容の違いが比較時間の差として漏れないようにする簡易的な定数時間比較
function timingSafeEqual(a, b) {
  const aBytes = new TextEncoder().encode(a);
  const bBytes = new TextEncoder().encode(b);
  const maxLength = Math.max(aBytes.length, bBytes.length);
  let diff = aBytes.length === bBytes.length ? 0 : 1;
  for (let i = 0; i < maxLength; i++) {
    diff |= (aBytes[i] || 0) ^ (bBytes[i] || 0);
  }
  return diff === 0;
}
