# Migración a VM.Standard.A1.Flex (4 OCPU / 24 GB) — Guía completa

## Paso 1: Crear nueva VM en OCI Console

1. Compute → Instances → Create Instance
2. **Shape**: VM.Standard.A1.Flex → OCPUs: 4, RAM: 24 GB
3. **Imagen**: Oracle Linux 8 (misma que la VM actual)
4. **Red**: misma VCN y subnet que la VM actual
5. **SSH Key**: subir `oci_soc.pub` (la misma key)
6. **Boot volume**: 50 GB mínimo
7. Anotar la IP pública de la nueva VM

## Paso 2: Preparar la nueva VM

```bash
NEW_IP=<ip-de-nueva-vm>

# Conectar a la nueva VM
ssh -i ~/.ssh/soc-key.pem opc@$NEW_IP

# En la nueva VM:
sudo dnf install -y git docker
sudo systemctl enable --now docker
sudo usermod -aG docker opc
# Cerrar sesión y reconectar para que el grupo docker aplique
exit
```

## Paso 3: Clonar el código

```bash
ssh -i ~/.ssh/soc-key.pem opc@$NEW_IP

# Clonar repo
git clone https://github.com/SDV244/SOC-Dashboard.git soc-dashboard
cd soc-dashboard

# Crear .env con credenciales reales (copiar desde VM vieja)
# Opción A: copiar directamente entre VMs
scp -i ~/.ssh/soc-key.pem opc@149.130.177.63:/home/opc/soc-dashboard/.env .
scp -i ~/.ssh/soc-key.pem opc@149.130.177.63:/home/opc/soc-dashboard/config.yaml .

# Opción B: crear manualmente copiando valores del .env.example
```

## Paso 4: Transferir el Block Volume de 200 GB (datos parquet)

**En OCI Console:**
1. Storage → Block Volumes → encontrar el volumen de 200 GB adjunto a la VM vieja
2. **Detach** el volumen de la VM vieja (requiere que la VM esté detenida o el volumen sea separable en caliente — verificar)
3. **Attach** el volumen a la nueva VM (como /dev/sdb o similar)

**En la nueva VM — montar el volumen:**
```bash
# Ver el dispositivo (normalmente /dev/sdb o /dev/nvme1n1)
lsblk

# Crear punto de montaje y montar
sudo mkdir -p /data/parquet
sudo mount /dev/sdb /data/parquet

# Verificar que los datos están
ls /data/parquet/

# Hacer el montaje permanente
echo '/dev/sdb /data/parquet xfs defaults,nofail 0 2' | sudo tee -a /etc/fstab
```

## Paso 5: Build y arranque

```bash
cd /home/opc/soc-dashboard

# Build de la imagen Docker (primera vez tarda ~5 min)
docker compose build

# Arrancar
docker compose up -d

# Verificar logs
docker compose logs -f
```

## Paso 6: Migrar crontab

```bash
# Copiar crontab desde la VM vieja
ssh -i ~/.ssh/soc-key.pem opc@149.130.177.63 "crontab -l"
# Pegar el output en:
crontab -e
```

## Paso 7: Verificar y apagar VM vieja

1. Probar el dashboard en la IP de la nueva VM
2. Actualizar cualquier DNS/VPN que apunte a la IP vieja
3. Una vez confirmado, **detener** (no borrar) la VM vieja por 1-2 semanas como respaldo
4. Después borrar la VM vieja para no acumular costos

## Notas A1.Flex (ARM)

- Python y DuckDB tienen builds ARM nativos — funcionan sin cambios
- Las imágenes Docker oficiales son multi-arch — `docker pull` baja la versión ARM automáticamente
- El Dockerfile actual usa `python:3.11-slim` que tiene versión ARM → no requiere cambios

## Comandos útiles de diagnóstico en nueva VM

```bash
# Ver uso de recursos
docker stats soc-dashboard-soc-1

# Ver logs del app
docker compose logs --tail 50 -f

# Verificar parquets accesibles
docker compose run --rm soc python -c \
  "import duckdb; c=duckdb.connect(':memory:'); \
   r=c.execute(\"SELECT count(*) FROM parquet_scan('/data/parquet/index=wineventlog/**/day=*.parquet')\").fetchone(); \
   print('wineventlog rows:', r[0])"
```
