import ida_kernwin
import idc


def print_banner():
    banner = """
    ==========================================
    |     Welcome to the IDA Python Script    |
    |          Developed by QM4RS             |
    ==========================================
    """
    print(banner)


def get_dump_file():
    path = ida_kernwin.ask_file(0, "*.cs", "Select dump.cs file")
    if path:
        return path
    else:
        return None


def extract_classes_and_methods(file_path):
    classes = {}
    current_class = None
    inside_class = False

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if line.startswith("class "):
                current_class = line.split()[1].split(':')[0]
                classes[current_class] = {"fields": [], "methods": []}
                inside_class = True
                continue

            if inside_class:
                if ";" in line and "(" not in line:
                    field_name = line.split()[1].split(";")[0]
                    classes[current_class]["fields"].append(field_name)

                elif "(" in line and ")" in line:
                    method_name = line.split()[1].split("(")[0]
                    offset = None
                    if "//" in line:
                        potential_offset = line.split("//")[-1].strip()
                        if potential_offset.startswith("0x"):
                            potential_offset = potential_offset[2:]
                        if is_hex(potential_offset):
                            offset = potential_offset

                    args = line[line.find("(") + 1: line.find(")")].split(", ")

                    arg_types = []
                    arg_names = []
                    for arg in args:
                        parts = arg.split()
                        if len(parts) == 2:
                            arg_types.append(parts[0])
                            arg_names.append(parts[1])

                    args_with_types = ", ".join(
                        [f"{arg_type} {arg_name}" for arg_type, arg_name in zip(arg_types, arg_names)])

                    method_info = {
                        "name": method_name,
                        "offset": offset,
                        "args": args_with_types
                    }
                    classes[current_class]["methods"].append(method_info)

                if line.startswith("}"):
                    inside_class = False

    return classes


def apply_method_names(classes):
    for class_name, details in classes.items():
        for method in details["methods"]:
            offset = int(method['offset'], 16) if method['offset'] else None
            if offset and idc.get_func_name(offset):
                full_name = f"{class_name}::{method['name']}"
                idc.set_name(offset, full_name, SN_NOWARN | SN_NOCHECK)
                args_comment = f"Args: {method['args']}"
                idc.set_func_cmt(offset, args_comment, 1)


def main():
    print_banner()
    dump_file = get_dump_file()

    if dump_file:
        class_methods = extract_classes_and_methods(dump_file)
        apply_method_names(class_methods)
        print("Method names and comments applied successfully!")
    else:
        print("No file selected!")

main()
