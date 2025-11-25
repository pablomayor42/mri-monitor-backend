import os
import argparse

def procesar_directorio(directorio_base, archivo_salida="output.txt", extensiones=None):
    """
    Procesa todos los archivos de un directorio y genera un archivo con rutas y contenido.
    
    Args:
        directorio_base (str): Ruta del directorio a procesar
        archivo_salida (str): Nombre del archivo de salida
        extensiones (list): Lista de extensiones a incluir (None para todas)
    """
    # Si no se especifican extensiones, incluir todos los archivos
    if extensiones is None:
        extensiones = []
    
    try:
        with open(archivo_salida, 'w', encoding='utf-8') as f_salida:
            # Recorrer todos los archivos y subdirectorios
            for raiz, directorios, archivos in os.walk(directorio_base):
                for archivo in archivos:
                    ruta_completa = os.path.join(raiz, archivo)
                    
                    # Verificar extensión si se especificaron extensiones
                    if extensiones:
                        _, ext = os.path.splitext(archivo)
                        if ext.lower() not in [e.lower() for e in extensiones]:
                            continue
                    
                    # Obtener ruta relativa
                    try:
                        ruta_relativa = os.path.relpath(ruta_completa, directorio_base)
                    except ValueError:
                        ruta_relativa = ruta_completa
                    
                    try:
                        # Leer contenido del archivo
                        with open(ruta_completa, 'r', encoding='utf-8') as f_entrada:
                            contenido = f_entrada.read()
                        
                        # Escribir en el archivo de salida
                        f_salida.write(f"--- RUTA: {ruta_relativa} ---\n")
                        f_salida.write(contenido)
                        f_salida.write("\n\n" + "="*80 + "\n\n")
                        
                        print(f"Procesado: {ruta_relativa}")
                        
                    except UnicodeDecodeError:
                        # Si no se puede leer como texto, marcarlo como binario
                        f_salida.write(f"--- RUTA: {ruta_relativa} ---\n")
                        f_salida.write("[ARCHIVO BINARIO - NO SE PUEDE LEER COMO TEXTO]\n")
                        f_salida.write("\n\n" + "="*80 + "\n\n")
                        print(f"Archivo binario omitido: {ruta_relativa}")
                    
                    except Exception as e:
                        f_salida.write(f"--- RUTA: {ruta_relativa} ---\n")
                        f_salida.write(f"[ERROR AL LEER ARCHIVO: {str(e)}]\n")
                        f_salida.write("\n\n" + "="*80 + "\n\n")
                        print(f"Error procesando {ruta_relativa}: {e}")
        
        print(f"\nProceso completado. Archivo generado: {archivo_salida}")
        
    except Exception as e:
        print(f"Error general: {e}")

def main():
    """Función principal con interfaz de línea de comandos."""
    parser = argparse.ArgumentParser(description='Consolida archivos de un directorio en un solo archivo')
    parser.add_argument('directorio', help='Directorio base a procesar')
    parser.add_argument('-o', '--output', default='output.txt', help='Archivo de salida (default: output.txt)')
    parser.add_argument('-e', '--extensiones', nargs='+', help='Extensiones a incluir (ej: .txt .py .js)')
    
    args = parser.parse_args()
    
    # Verificar que el directorio existe
    if not os.path.exists(args.directorio):
        print(f"Error: El directorio '{args.directorio}' no existe.")
        return
    
    procesar_directorio(args.directorio, args.output, args.extensiones)

if __name__ == "__main__":
    # Si se ejecuta sin argumentos, usar valores por defecto
    import sys
    if len(sys.argv) > 1:
        main()
    else:
        # Ejemplo de uso interactivo
        directorio = input("Ingrese la ruta del directorio a procesar: ").strip()
        if not directorio:
            directorio = "."  # Directorio actual
        
        archivo_salida = input("Ingrese el nombre del archivo de salida (default: output.txt): ").strip()
        if not archivo_salida:
            archivo_salida = "output.txt"
        
        extensiones_input = input("Ingrese extensiones a incluir separadas por espacio (ej: .txt .py) o Enter para todas: ").strip()
        extensiones = extensiones_input.split() if extensiones_input else None
        
        procesar_directorio(directorio, archivo_salida, extensiones)