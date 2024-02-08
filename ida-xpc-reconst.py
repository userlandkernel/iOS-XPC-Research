import idaapi
import idc

# Define the xpc message structure
class xpc_message_t(idaapi.struc_t):
    def __init__(self, name):
        idaapi.struc_t.__init__(self, idaapi.get_struc_id(name))
        self.name = name
        self.size = idaapi.get_struc_size(self.id)
        self.members = {}
        for i in range(self.memqty):
            m = self.get_member(i)
            self.members[m.name] = m

# Create an xpc message structure with the given name and fields
def create_xpc_message(name, fields):
    sid = idaapi.add_struc(-1, name, 0)
    if sid == idaapi.BADADDR:
        print("Failed to create structure %s" % name)
        return None
    s = xpc_message_t(name)
    offset = 0
    for f in fields:
        fname, ftype, fsize = f
        if idaapi.add_struc_member(s, fname, offset, ftype, -1, fsize) != 0:
            print("Failed to add member %s to structure %s" % (fname, name))
            return None
        offset += fsize
    return s

# Find all xrefs to the xpc_send_message function
def find_xpc_send_message_xrefs():
    xrefs = []
    ea = idc.get_name_ea_simple("xpc_send_message")
    if ea == idaapi.BADADDR:
        print("Could not find xpc_send_message function")
        return xrefs
    for xref in idautils.XrefsTo(ea, 0):
        xrefs.append(xref.frm)
    return xrefs

# Extract the xpc message from the given address
def extract_xpc_message(ea):
    # Get the function that calls xpc_send_message
    func = idaapi.get_func(ea)
    if not func:
        print("Could not get function at 0x%X" % ea)
        return None
    # Get the basic block that contains the call
    block = idaapi.FlowChart(func).find_basic_block(ea)
    if not block:
        print("Could not get basic block at 0x%X" % ea)
        return None
    # Get the instruction that sets the first argument (x0) to the xpc message pointer
    msg_ea = idaapi.BADADDR
    for head in idautils.Heads(block.start_ea, block.end_ea):
        if head >= ea:
            break
        mnem = idc.print_insn_mnem(head)
        if mnem == "ADR" and idc.print_operand(head, 0) == "X0":
            msg_ea = idc.get_operand_value(head, 1)
            break
    if msg_ea == idaapi.BADADDR:
        print("Could not find xpc message pointer at 0x%X" % ea)
        return None
    # Get the xpc message name from the string at the pointer
    msg_name = idc.get_strlit_contents(msg_ea)
    if not msg_name:
        print("Could not get xpc message name at 0x%X" % ea)
        return None
    # Get the xpc message fields from the data after the pointer
    msg_fields = []
    offset = idc.get_item_size(msg_ea)
    while True:
        # Get the field name from the string at the offset
        field_name = idc.get_strlit_contents(msg_ea + offset)
        if not field_name:
            break
        # Get the field type and size from the byte after the string
        field_type = idc.get_wide_byte(msg_ea + offset + len(field_name) + 1)
        field_size = idc.get_item_size(msg_ea + offset + len(field_name) + 2)
        # Add the field to the list
        msg_fields.append((field_name, field_type, field_size))
        # Move to the next field
        offset += len(field_name) + 2 + field_size
    # Create the xpc message structure
    msg_struct = create_xpc_message(msg_name, msg_fields)
    if not msg_struct:
        print("Could not create xpc message structure for %s" % msg_name)
        return None
    # Return the xpc message structure
    return msg_struct

# Generate c code to send the xpc message
def generate_xpc_message_c_code(msg_struct):
    # Create a buffer to store the c code
    c_code = ""
    # Include the xpc headers
    c_code += "#include <xpc/xpc.h>\n"
    c_code += "#include <xpc/connection.h>\n\n"
    # Declare the xpc message structure
    c_code += "struct %s {\n" % msg_struct.name
    for m in msg_struct.members.values():
        c_code += "\tchar %s[%d];\n" % (m.name, m.size)
    c_code += "};\n\n"
    # Define a function to send the xpc message
    c_code += "void send_%s(xpc_connection_t conn) {\n" % msg_struct.name
    # Create the xpc message object
    c_code += "\txpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);\n"
    # Set the xpc message name
    c_code += "\txpc_dictionary_set_string(msg, \"name\", \"%s\");\n" % msg_struct.name
    # Set the xpc message fields
    for m in msg_struct.members.values():
        # Get the field type and value
        field_type = idc.get_wide_byte(m.ea + len(m.name) + 1)
        field_value = idc.get_bytes(m.ea + len(m.name) + 2, m.size)
        # Convert the field value to hex string
        field_value_hex = "".join(["\\x%02X" % b for b in field_value])
        # Set the field according to the type
        if field_type == 0x01: # XPC_TYPE_BOOL
            c_code += "\txpc_dictionary_set_bool(msg, \"%s\", %s);\n" % (m.name, "true" if field_value[0] else "false")
        elif field_type == 0x02: # XPC_TYPE_INT64
            c_code += "\txpc_dictionary_set_int64(msg, \"%s\", *(int64_t*)\"%s\");\n" % (m.name, field_value_hex)
        elif field_type == 0x03: # XPC_TYPE_UINT64
            c_code += "\txpc_dictionary_set_uint64(msg, \"%s\", *(uint64_t*)\"%s\");\n" % (m.name, field_value_hex)
        elif field_type == 0x04: # XPC_TYPE_DOUBLE
            c_code += "\txpc_dictionary_set_double(msg, \"%s\", *(double*)\"%s\");\n" % (m.name, field_value_hex)
        elif field_type == 0x05: # XPC_TYPE_DATE
            c_code += "\txpc_dictionary_set_date(msg, \"%s\", *(int64_t*)\"%s\");\n" % (m.name, field_value_hex)
        elif field_type == 0x06: # XPC_TYPE_DATA
            c_code += "\txpc_dictionary_set_data(msg, \"%s\", \"%s\", %d);\n" % (m.name, field_value_hex, m.size)
        elif field_type == 0x07: # XPC_TYPE_STRING
            c_code += "\txpc_dictionary_set_string(msg, \"%s\", \"%s\");\n" % (m.name, field_value.decode("utf-8"))
        elif field_type == 0x08: # XPC_TYPE_UUID
            c_code += "\txpc_dictionary_set_uuid(msg, \"%s\", \"%s\");\n" % (m.name, field_value_hex)
        elif field_type == 0x09: # XPC_TYPE_FD
            c_code += "\txpc_dictionary_set_fd(msg, \"%s\", *(int*)\"%s\");\n" % (m.name, field_value_hex)
        elif field_type == 0x0A: # XPC_TYPE_SHMEM
            c_code += "\txpc_dictionary_set_shmem(msg, \"%s\", *(xpc_shmem_t*)\"%s\");\n" % (m.name, field_value_hex)
        elif field_type == 0x0B: # XPC_TYPE_ARRAY
            c_code += "\t// TODO: handle XPC_TYPE_ARRAY for field %s\n" % m.name
        elif field_type == 0x0C: # XPC_TYPE_DICTIONARY
            c_code += "\t// TODO: handle XPC_TYPE_DICTIONARY for field %s\n" % m.name
        else:
            c_code += "\t// Unknown field type 0x%02X for field %s\n" % (field_type, m.name)
