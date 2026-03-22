# 🏠 CasaID — Gestor familiar de documentos de identidad

Aplicación web minimalista y segura para que los miembros de una familia
gestionen sus DNIs y documentos de identidad.

---

## ✨ Características

| Feature | Detalle |
|---|---|
| 🔐 Autenticación | SQLite + bcrypt (hash seguro de contraseñas) |
| 🔒 Cifrado de archivos | Fernet (AES-128-CBC) — archivos nunca en texto plano |
| 👤 Aislamiento de usuarios | Cada usuario solo ve sus propios documentos |
| 📄 Formatos soportados | PDF, JPG, PNG, WEBP (hasta 20 MB) |
| 👁️ Previsualización | PDF inline + imágenes directamente en el navegador |
| ⬇️ Descarga | Archivo descifrado al vuelo con un clic |
| 🟢 Compartir | Botón de WhatsApp integrado |
| 🗑️ Borrado seguro | Elimina el cifrado del disco y el registro de BD |

---

## 🚀 Despliegue local

### Requisitos previos
- Python 3.10 o superior
- pip

### 1. Instalar dependencias

```bash
cd "Mis Aplicaciones/CasaID"
pip install -r requirements.txt
```

> **Nota sobre PyMuPDF:** si la instalación falla en Windows, usa:
> ```bash
> pip install pymupdf --no-binary pymupdf
> ```

### 2. Ejecutar la aplicación

```bash
streamlit run app.py
```

Abre tu navegador en: **http://localhost:8501**

---

## ☁️ Despliegue en Streamlit Cloud (gratuito)

1. Sube el repositorio a GitHub (asegúrate de incluir `requirements.txt`).
2. Ve a [share.streamlit.io](https://share.streamlit.io) e inicia sesión con GitHub.
3. Haz clic en **"New app"** → selecciona tu repo → `app.py` como archivo principal.
4. Haz clic en **Deploy**.

> ⚠️ **Importante en la nube:** La clave Fernet (`.fernet.key`) y la base de
> datos SQLite se almacenan en el sistema de archivos efímero de Streamlit Cloud.
> **Se borran con cada redeploy.** Para producción, usa:
> - [Streamlit Secrets](https://docs.streamlit.io/streamlit-community-cloud/deploy-your-app/secrets-management) para la clave Fernet.
> - [Supabase](https://supabase.com) o [PlanetScale](https://planetscale.com) para la BD.
> - [Cloudflare R2](https://www.cloudflare.com/products/r2/) o similar para los archivos cifrados.

---

## 🗂️ Estructura de archivos

```
CasaID/
├── app.py                  # Aplicación principal
├── requirements.txt        # Dependencias Python
├── .streamlit/
│   └── config.toml         # Tema oscuro personalizado
└── data/                   # Creado automáticamente al iniciar
    ├── casaid.db           # Base de datos SQLite
    ├── .fernet.key         # Clave de cifrado (¡no subir a git!)
    └── uploads/            # Archivos cifrados (.enc)
```

---

## 🔒 Notas de seguridad

- La clave Fernet se genera **una sola vez** y se almacena en `data/.fernet.key`.
  **Haz una copia de seguridad de este archivo.** Sin él, los documentos son
  irrecuperables.
- Las contraseñas se almacenan como hash bcrypt con salt aleatorio.
- Los archivos en disco tienen extensión `.enc` y nombres UUID (no deducibles).
- Agrega `data/` a tu `.gitignore` para no exponer datos sensibles.

---

## 🛑 .gitignore recomendado

```
data/
__pycache__/
*.pyc
.env
```
