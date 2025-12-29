import struct
import sys
from datetime import datetime


class FAT16Parser:
    def __init__(self, dump_file):
        print("Введите путь до файла: ")
        self.dump_file = input().replace("\\", "/")
        self.dump_data = None
        self.boot_sector = {}
        self.files = []

        print("=" * 70)
        print("Анализ дампа раздела FAT16")
        print("=" * 70)

        self.load_dump()

    def load_dump(self):
        """Загружает дамп из файла в переменную"""
        print(f"\n1. Загрузка дампа из файла: {self.dump_file}")
        print("-" * 40)


        try:
            with open(self.dump_file, 'rb') as f:
                self.dump_data = f.read()

            size_mb = len(self.dump_data) / (1024 * 1024)
            print(f"  Дамп загружен в переменную 'dump_data'")
            print(f"  Размер: {len(self.dump_data):,} байт ({size_mb:.1f} МБ)")
            print(f"  Тип данных: {type(self.dump_data)}")

            if len(self.dump_data) >= 512:
                if self.dump_data[510] == 0x55 and self.dump_data[511] == 0xAA:
                    print("✓ Обнаружена сигнатура FAT (55 AA)")
                else:
                    print("✗ Нет сигнатуры FAT!")
                    return False
            else:
                print("✗ Слишком маленький для загрузочного сектора!")
                return False

            return True

        except FileNotFoundError:
            print(f"✗ Ошибка: файл '{self.dump_file}' не найден!")
            return False
        except Exception as e:
            print(f"✗ Ошибка при загрузке: {e}")
            return False

    def parse_boot_sector(self):
        """Анализирует загрузочный сектор для больших томов (>32 МБ)"""
        print("\n2. Анализ загрузочного сектора")
        print("-" * 40)

        data = self.dump_data

        # Базовые параметры
        self.boot_sector['bytes_per_sector'] = struct.unpack_from('<H', data, 0x0B)[0]
        self.boot_sector['sectors_per_cluster'] = data[0x0D]
        self.boot_sector['reserved_sectors'] = struct.unpack_from('<H', data, 0x0E)[0]
        self.boot_sector['num_fats'] = data[0x10]
        self.boot_sector['max_root_entries'] = struct.unpack_from('<H', data, 0x11)[0]
        self.boot_sector['media_descriptor'] = data[0x15]

        # Для больших разделов используем 32-битное total_sectors
        total_sectors_16 = struct.unpack_from('<H', data, 0x13)[0]
        total_sectors_32 = struct.unpack_from('<I', data, 0x20)[0]

        if total_sectors_32 > 0:
            self.boot_sector['total_sectors'] = total_sectors_32
            print(f"✓ Используем 32-битное total_sectors: {total_sectors_32}")
        else:
            self.boot_sector['total_sectors'] = total_sectors_16
            print(f"Используем 16-битное total_sectors: {total_sectors_16}")

        # Sectors per FAT
        self.boot_sector['sectors_per_fat'] = struct.unpack_from('<H', data, 0x16)[0]
        if self.boot_sector['sectors_per_fat'] == 0:
            self.boot_sector['sectors_per_fat'] = struct.unpack_from('<H', data, 0x24)[0]

        # Дополнительная информация
        self.boot_sector['oem_name'] = data[0x03:0x0B].decode('ascii', errors='ignore').strip()
        self.boot_sector['fs_type'] = data[0x36:0x3E].decode('ascii', errors='ignore').strip()
        self.boot_sector['volume_label'] = data[0x2B:0x36].decode('ascii', errors='ignore').strip()

        # Выводим информацию
        print(f"\nОсновные параметры:")
        print(f"  • OEM Name: '{self.boot_sector['oem_name']}'")
        print(f"  • Байт на сектор: {self.boot_sector['bytes_per_sector']}")
        print(f"  • Секторов на кластер: {self.boot_sector['sectors_per_cluster']}")
        print(f"  • Зарезервированных секторов: {self.boot_sector['reserved_sectors']}")
        print(f"  • Количество таблиц FAT: {self.boot_sector['num_fats']}")
        print(f"  • Макс. записей в корневом каталоге: {self.boot_sector['max_root_entries']}")
        print(f"  • Секторов на FAT: {self.boot_sector['sectors_per_fat']}")
        print(f"  • Всего секторов: {self.boot_sector['total_sectors']}")
        print(f"  • Дескриптор носителя: 0x{self.boot_sector['media_descriptor']:02X}")
        print(f"  • Тип ФС: '{self.boot_sector['fs_type']}'")
        print(f"  • Метка тома: '{self.boot_sector['volume_label']}'")

        # Вычисляем размер
        total_bytes = self.boot_sector['total_sectors'] * self.boot_sector['bytes_per_sector']
        total_mb = total_bytes / (1024 * 1024)
        print(f"  • Размер раздела: {total_mb:.1f} МБ")

        # Вычисляем смещения
        self.boot_sector['fat_start'] = self.boot_sector['reserved_sectors'] * self.boot_sector['bytes_per_sector']
        self.boot_sector['fat_size'] = self.boot_sector['sectors_per_fat'] * self.boot_sector['bytes_per_sector']
        self.boot_sector['root_dir_start'] = self.boot_sector['fat_start'] + (
                    self.boot_sector['num_fats'] * self.boot_sector['fat_size'])
        self.boot_sector['root_dir_size'] = self.boot_sector['max_root_entries'] * 32
        self.boot_sector['data_start'] = self.boot_sector['root_dir_start'] + self.boot_sector['root_dir_size']

        print(f"\nСмещения в дампе:")
        print(f"  • Начало FAT: 0x{self.boot_sector['fat_start']:08X}")
        print(f"  • Начало корневого каталога: 0x{self.boot_sector['root_dir_start']:08X}")
        print(f"  • Начало области данных: 0x{self.boot_sector['data_start']:08X}")

        return True

    def parse_root_directory(self):
        """Парсит корневой каталог и выводит информацию"""
        print("\n3. Корневой каталог")
        print("-" * 40)

        if not self.boot_sector:
            print("Сначала проанализируйте загрузочный сектор!")
            return []

        root_start = self.boot_sector['root_dir_start']
        max_entries = self.boot_sector['max_root_entries']

        print(f"Смещение: 0x{root_start:08X}")
        print(f"Максимум записей: {max_entries}")
        print("\nСодержимое корневого каталога:")
        print("-" * 60)

        self.files = []

        for i in range(max_entries):
            entry_offset = root_start + (i * 32)

            if entry_offset + 32 > len(self.dump_data):
                break

            first_byte = self.dump_data[entry_offset]

            # Конец каталога
            if first_byte == 0x00:
                print(f"\nКонец каталога достигнут на записи {i}")
                break

            # Удалённый файл
            if first_byte == 0xE5:
                continue

            # Читаем имя
            name_bytes = self.dump_data[entry_offset:entry_offset + 8]
            name = ""
            for b in name_bytes:
                if b == 0x20 or b == 0x00:
                    break
                if 32 <= b < 127:
                    name += chr(b)
                else:
                    name += '.'

            # Читаем расширение
            ext_bytes = self.dump_data[entry_offset + 8:entry_offset + 11]
            ext = ""
            for b in ext_bytes:
                if b == 0x20 or b == 0x00:
                    break
                if 32 <= b < 127:
                    ext += chr(b)
                else:
                    ext += '.'

            # Атрибуты
            attr = self.dump_data[entry_offset + 11]

            # Пропускаем специальные записи
            is_volume = bool(attr & 0x08)
            is_long_name = (attr == 0x0F)

            if is_volume or is_long_name:
                continue

            # Пропускаем пустые
            if all(b == 0x20 or b == 0x00 for b in name_bytes) and all(b == 0x20 or b == 0x00 for b in ext_bytes):
                continue

            # Читаем параметры файла
            try:
                cluster_high = struct.unpack_from('<H', self.dump_data, entry_offset + 20)[0]
                cluster_low = struct.unpack_from('<H', self.dump_data, entry_offset + 26)[0]
                cluster = (cluster_high << 16) | cluster_low
                file_size = struct.unpack_from('<I', self.dump_data, entry_offset + 28)[0]

                # Формируем имя
                full_name = name.strip()
                is_dir = bool(attr & 0x10)

                if not is_dir and ext.strip():
                    full_name = f"{name.strip()}.{ext.strip()}"
                elif is_dir:
                    full_name = f"[{name.strip()}]"

                # Сохраняем
                file_info = {
                    'name': full_name,
                    'is_dir': is_dir,
                    'cluster': cluster,
                    'size': file_size,
                    'entry_offset': entry_offset
                }

                self.files.append(file_info)

                # Выводим
                type_str = "DIR" if is_dir else "FILE"
                print(f"{i:3d}. {full_name:20} {type_str:4} "
                      f"cluster:{cluster:6d} size:{file_size:8d} байт")

            except Exception as e:
                print(f"Ошибка в записи {i}: {e}")

        print(f"\nВсего файлов/каталогов: {len(self.files)}")
        return self.files

    def find_hello_file(self):
        """Ищет файл hello_file.txt"""
        print("\n4. Поиск файла hello_file.txt")
        print("-" * 40)

        if not self.files:
            print("Файлы не найдены в корневом каталоге!")
            return None

        # Возможные имена
        search_patterns = ['HELLO', 'MY_TEST', 'TEST', '.TXT']
        found_files = []

        for file_info in self.files:
            if file_info['is_dir']:
                continue

            name_upper = file_info['name'].upper()
            for pattern in search_patterns:
                if pattern in name_upper:
                    found_files.append(file_info)
                    break

        if found_files:
            print(f"Найдено {len(found_files)} файл(ов):")
            for i, file_info in enumerate(found_files):
                print(f"  {i}. {file_info['name']} ({file_info['size']} байт)")

            # Возвращаем первый найденный
            return found_files[0]
        else:
            print("hello_file.txt не найден.")
            print("\nВсе файлы в корневом каталоге:")
            for i, file_info in enumerate(self.files):
                if not file_info['is_dir']:
                    print(f"  {i}. {file_info['name']} ({file_info['size']} байт)")


            try:
                choice = input("\nВведите номер файла для чтения: ")
                idx = int(choice)
                if 0 <= idx < len(self.files) and not self.files[idx]['is_dir']:
                    return self.files[idx]
            except:
                print("Неверный ввод.")

        return None

    def read_file_structure(self, file_info):
        """Читает и выводит структуру файла"""
        print(f"\n5. Структура файла: {file_info['name']}")
        print("-" * 40)

        if file_info['is_dir']:
            print("Это каталог, структура не читается.")
            return

        if file_info['size'] == 0:
            print("Файл пуст.")
            return

        # Вычисляем смещение
        cluster_size = self.boot_sector['sectors_per_cluster'] * self.boot_sector['bytes_per_sector']
        data_start = self.boot_sector['data_start']

        cluster_num = file_info['cluster']
        if cluster_num < 2:
            print(f"Неверный номер кластера: {cluster_num}")
            return

        cluster_offset = data_start + ((cluster_num - 2) * cluster_size)

        print(f"Параметры файла:")
        print(f"  • Имя: {file_info['name']}")
        print(f"  • Размер: {file_info['size']} байт")
        print(f"  • Начальный кластер: {cluster_num}")
        print(f"  • Смещение в дампе: 0x{cluster_offset:08X}")
        print(f"  • Размер кластера: {cluster_size} байт")

        # Проверяем границы
        if cluster_offset >= len(self.dump_data):
            print("Ошибка: смещение за пределами дампа!")
            return

        # Читаем данные
        end_offset = min(cluster_offset + file_info['size'], len(self.dump_data))
        file_data = self.dump_data[cluster_offset:end_offset]

        actual_size = len(file_data)
        print(f"  • Прочитано байт: {actual_size}")

        # Пытаемся декодировать как текст
        print(f"\nТекстовое содержимое:")

        encodings = ['utf-8', 'ascii', 'cp1251', 'latin-1']
        decoded = False

        for encoding in encodings:
            try:
                text = file_data.decode(encoding)
                print(f"✓ Кодировка {encoding}:")
                print('"' + text + '"')
                decoded = True
                break
            except:
                continue

        if not decoded:
            print("Не удалось декодировать как текст")

        # Hex-дамп структуры
        print(f"\nHEX-Структура файла (первые 96 байт):")
        print("-" * 60)

        for i in range(0, min(96, actual_size), 16):
            chunk = file_data[i:i + 16]
            hex_str = ' '.join(f'{b:02X}' for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            print(f"{cluster_offset + i:08X}: {hex_str:<48} |{ascii_str}|")

        if actual_size > 96:
            print(f"... и ещё {actual_size - 96} байт")

    def show_fat_table_info(self):
        """Показывает информацию о таблице FAT"""
        print("\n6. Информация о таблице FAT")
        print("-" * 40)

        fat_start = self.boot_sector['fat_start']

        print(f"Смещение таблицы FAT: 0x{fat_start:08X}")
        print(f"Размер одной FAT: {self.boot_sector['fat_size']} байт")
        print(f"Количество копий FAT: {self.boot_sector['num_fats']}")

        # Показываем первые записи
        print(f"\nПервые 8 записей FAT:")
        for i in range(8):
            offset = fat_start + (i * 2)
            if offset + 2 <= len(self.dump_data):
                value = struct.unpack_from('<H', self.dump_data, offset)[0]

                if i == 0:
                    desc = f"(Media descriptor: 0x{value:04X})"
                elif i == 1:
                    desc = "(Reserved)"
                elif value == 0x0000:
                    desc = "(Free cluster)"
                elif value >= 0xFFF8:
                    desc = "(End of chain)"
                elif value == 0xFFF7:
                    desc = "(Bad cluster)"
                else:
                    desc = f"(Next cluster: {value})"

                print(f"  FAT[{i}] = 0x{value:04X} {desc}")

    def run(self):
        """Запускает полный анализ"""
        print("\n" + "=" * 70)
        print("Анализ")
        print("=" * 70)

        # 1. Загрузка дампа
        if not self.load_dump():
            return

        # 2. Анализ загрузочного сектора
        if not self.parse_boot_sector():
            return

        # 3. Анализ корневого каталога
        self.parse_root_directory()

        # 4. Поиск hello_file.txt
        target_file = self.find_hello_file()

        # 5. Чтение структуры файла
        if target_file:
            self.read_file_structure(target_file)
        else:
            print("\nНе найден файл для анализа структуры.")

        # 6. Информация о FAT
        self.show_fat_table_info()

        print("\n" + "=" * 70)
        print("Анализ завершен")
        print("=" * 70)
        print(f"Дамп загружен в переменную 'dump_data' ({len(self.dump_data):,} байт)")
        print(f"Найдено файлов/каталогов: {len(self.files)}")


# Запуск программы
def main():
    """Основная функция"""
    parser = FAT16Parser("dump_fat16.bin")
    parser.run()


if __name__ == "__main__":
    main()
    input()