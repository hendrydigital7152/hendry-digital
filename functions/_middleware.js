const PASSWORD = "GantiDenganPasswordKuat";

export async function onRequest(context) {
  const { request, next, env } = context;
  const url = new URL(request.url);

  if (url.pathname === "/login" && request.method === "POST") {
    const form = await request.formData();

    if (form.get("password") === env.SITE_PASSWORD) {
      return new Response("Password benar. Sistem login perlu dilengkapi sebelum digunakan.", {
        status: 200
      });
    }

    return new Response("Password salah.", { status: 401 });
  }

  return next();
}
