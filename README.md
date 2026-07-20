# Auditorías KH

Panel web de auditorías internas (Process Confirmation) con Flask y SQLite.

## Requisitos

- Python 3.14+

## Puesta en marcha

```bash
pip install -r requirements.txt
cp .env.example .env   # editar y rellenar los valores
python app.py
```

La aplicación queda disponible en el puerto configurado en `.env` (`APP_PORT`, 8000 por defecto).
