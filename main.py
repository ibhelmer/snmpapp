import asyncio
import os
import re
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from pysnmp.hlapi.v1arch.asyncio import (
    CommunityData,
    SnmpDispatcher,
    UdpTransportTarget,
    ObjectType,
    ObjectIdentity,
    get_cmd,
    next_cmd,
)

BUILTIN_SYMBOLS = {
    "Systemnavn": "SNMPv2-MIB::sysName.0",
    "Beskrivelse": "SNMPv2-MIB::sysDescr.0",
    "Oppetid": "DISMAN-EVENT-MIB::sysUpTimeInstance",
    "Kontakt": "SNMPv2-MIB::sysContact.0",
    "Placering": "SNMPv2-MIB::sysLocation.0",
    "Antal interfaces": "IF-MIB::ifNumber.0",
}

STATUS_MAP = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "notPresent",
    7: "lowerLayerDown",
}

STATUS_COLORS = {
    "up": "#d9f2d9",
    "down": "#f8d7da",
    "testing": "#fff3cd",
    "unknown": "#e2e3e5",
    "dormant": "#d1ecf1",
    "notPresent": "#e2e3e5",
    "lowerLayerDown": "#f8d7da",
}


def read_text_file_with_fallbacks(path: str) -> str:
    for encoding in ("utf-8", "latin-1", "cp1252"):
        try:
            with open(path, "r", encoding=encoding) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


class MibManager:
    def __init__(self):
        self.file_path = ""
        self.module_name = ""
        self.directory = ""
        self.symbols = []

    def clear(self):
        self.file_path = ""
        self.module_name = ""
        self.directory = ""
        self.symbols = []

    def load_file(self, filepath: str):
        if not filepath:
            self.clear()
            return
        if not os.path.isfile(filepath):
            raise FileNotFoundError("Den valgte MIB-fil findes ikke")

        text = read_text_file_with_fallbacks(filepath)
        module_name = self._extract_module_name(text, filepath)
        symbols = self._extract_symbols(text, module_name)

        self.file_path = filepath
        self.directory = os.path.dirname(os.path.abspath(filepath))
        self.module_name = module_name
        self.symbols = symbols

    def _extract_module_name(self, text: str, filepath: str) -> str:
        match = re.search(r"^\s*([A-Za-z0-9\-]+)\s+DEFINITIONS\s+::=\s+BEGIN", text, re.MULTILINE)
        if match:
            return match.group(1).strip()
        return os.path.splitext(os.path.basename(filepath))[0]

    def _extract_symbols(self, text: str, module_name: str):
        object_type_names = re.findall(
            r"^\s*([A-Za-z][A-Za-z0-9\-]*)\s+OBJECT-TYPE\b", text, re.MULTILINE
        )
        object_identity_names = re.findall(
            r"^\s*([A-Za-z][A-Za-z0-9\-]*)\s+OBJECT IDENTIFIER\b", text, re.MULTILINE
        )
        notification_names = re.findall(
            r"^\s*([A-Za-z][A-Za-z0-9\-]*)\s+NOTIFICATION-TYPE\b", text, re.MULTILINE
        )

        names = []
        seen = set()
        for name in object_type_names + object_identity_names + notification_names:
            if name not in seen:
                seen.add(name)
                names.append(name)

        entries = []
        for name in names:
            suffix = ".0" if name in object_type_names else ""
            entries.append(f"{module_name}::{name}{suffix}")
        return entries

    def build_identity(self, oid_text: str):
        oid_text = oid_text.strip()
        if not oid_text:
            raise ValueError("OID kan ikke være tom")

        if "::" not in oid_text:
            return ObjectIdentity(oid_text)

        mib_name, symbol_part = oid_text.split("::", 1)
        mib_name = mib_name.strip()
        symbol_part = symbol_part.strip()

        if not mib_name or not symbol_part:
            raise ValueError("Ugyldigt MIB-symbol. Brug formatet MIBNAVN::symbol.0")

        if "." in symbol_part:
            symbol_name, *index_parts = symbol_part.split(".")
            try:
                indices = tuple(int(p) for p in index_parts if p != "")
            except ValueError as exc:
                raise ValueError("OID-indeks skal være numeriske") from exc
        else:
            symbol_name = symbol_part
            indices = ()

        identity = ObjectIdentity(mib_name, symbol_name, *indices)
        if self.directory:
            identity = identity.add_mib_source(self.directory)
        identity = identity.load_mibs(mib_name)
        return identity


mib_manager = MibManager()


async def snmp_get(ip: str, community: str, port: int, oid_text: str, timeout: int = 2, retries: int = 1):
    obj_identity = mib_manager.build_identity(oid_text)
    iterator = get_cmd(
        SnmpDispatcher(),
        CommunityData(community),
        await UdpTransportTarget.create((ip, port), timeout=timeout, retries=retries),
        ObjectType(obj_identity),
    )

    error_indication, error_status, error_index, var_binds = await iterator

    if error_indication:
        raise RuntimeError(f"SNMP fejl: {error_indication}")
    if error_status:
        raise RuntimeError(f"SNMP agent fejl: {error_status.prettyPrint()} ved indeks {error_index}")
    if not var_binds:
        raise RuntimeError("Intet svar modtaget fra SNMP-agenten")

    for name, value in var_binds:
        return str(name), str(value)

    raise RuntimeError("Kunne ikke fortolke SNMP-svaret")


async def snmp_walk(ip: str, community: str, port: int, oid_text: str, timeout: int = 2, retries: int = 1):
    obj_identity = mib_manager.build_identity(oid_text)
    iterator = next_cmd(
        SnmpDispatcher(),
        CommunityData(community),
        await UdpTransportTarget.create((ip, port), timeout=timeout, retries=retries),
        ObjectType(obj_identity),
        lexicographicMode=False,
    )

    results = []
    async for error_indication, error_status, error_index, var_binds in iterator:
        if error_indication:
            raise RuntimeError(f"SNMP fejl: {error_indication}")
        if error_status:
            raise RuntimeError(f"SNMP agent fejl: {error_status.prettyPrint()} ved indeks {error_index}")
        for name, value in var_binds:
            results.append((str(name), str(value)))
    return results


async def read_summary(ip: str, community: str, port: int):
    results = {}
    for label, oid in BUILTIN_SYMBOLS.items():
        try:
            _, value = await snmp_get(ip, community, port, oid)
            results[label] = value
        except Exception as exc:
            results[label] = f"Fejl: {exc}"
    return results


async def read_interfaces(ip: str, community: str, port: int):
    names = await snmp_walk(ip, community, port, "1.3.6.1.2.1.2.2.1.2")
    statuses = await snmp_walk(ip, community, port, "1.3.6.1.2.1.2.2.1.8")
    in_octets = await snmp_walk(ip, community, port, "1.3.6.1.2.1.2.2.1.10")
    out_octets = await snmp_walk(ip, community, port, "1.3.6.1.2.1.2.2.1.16")

    def index_from_oid(oid: str):
        return oid.split(".")[-1]

    table = {}

    for oid, value in names:
        idx = index_from_oid(oid)
        table[idx] = {
            "name": value,
            "status": "unknown",
            "in_octets": "0",
            "out_octets": "0",
        }

    for oid, value in statuses:
        idx = index_from_oid(oid)
        code = int(value)
        table.setdefault(idx, {})
        table[idx]["status"] = STATUS_MAP.get(code, f"unknown({code})")

    for oid, value in in_octets:
        idx = index_from_oid(oid)
        table.setdefault(idx, {})
        table[idx]["in_octets"] = value

    for oid, value in out_octets:
        idx = index_from_oid(oid)
        table.setdefault(idx, {})
        table[idx]["out_octets"] = value

    rows = []
    for idx in sorted(table, key=lambda x: int(x)):
        item = table[idx]
        rows.append(
            {
                "index": idx,
                "name": item.get("name", f"if{idx}"),
                "status": item.get("status", "unknown"),
                "in_octets": item.get("in_octets", "0"),
                "out_octets": item.get("out_octets", "0"),
            }
        )
    return rows


class SNMPRouterGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SNMP Router Monitor v3")
        self.root.geometry("1220x800")

        self.ip_var = tk.StringVar(value="192.168.1.1")
        self.community_var = tk.StringVar(value="public")
        self.port_var = tk.StringVar(value="161")
        self.custom_oid_var = tk.StringVar(value=BUILTIN_SYMBOLS["Systemnavn"])
        self.known_symbol_var = tk.StringVar(value="Systemnavn")
        self.imported_symbol_var = tk.StringVar(value="")
        self.mib_file_var = tk.StringVar(value="")
        self.imported_count_var = tk.StringVar(value="Ingen MIB-fil valgt")
        self.polling_var = tk.BooleanVar(value=False)
        self.polling_job = None

        self._build_ui()
        self.apply_known_symbol()

    def _build_ui(self):
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill="both", expand=True)

        connection = ttk.LabelFrame(main, text="Forbindelse", padding=10)
        connection.pack(fill="x", pady=(0, 10))

        ttk.Label(connection, text="Router IP:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(connection, textvariable=self.ip_var, width=18).grid(row=0, column=1, sticky="w", padx=5, pady=5)
        ttk.Label(connection, text="Community:").grid(row=0, column=2, sticky="w", padx=5, pady=5)
        ttk.Entry(connection, textvariable=self.community_var, width=18, show="*").grid(row=0, column=3, sticky="w", padx=5, pady=5)
        ttk.Label(connection, text="Port:").grid(row=0, column=4, sticky="w", padx=5, pady=5)
        ttk.Entry(connection, textvariable=self.port_var, width=8).grid(row=0, column=5, sticky="w", padx=5, pady=5)
        ttk.Button(connection, text="Aflæs nu", command=self.refresh_all).grid(row=0, column=6, padx=8, pady=5)
        ttk.Checkbutton(
            connection,
            text="Live polling hvert 5. sekund",
            variable=self.polling_var,
            command=self.toggle_polling,
        ).grid(row=0, column=7, padx=10, pady=5, sticky="w")

        mib_frame = ttk.LabelFrame(main, text="MIB v3", padding=10)
        mib_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(mib_frame, text="Kendt symbol:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        builtin_combo = ttk.Combobox(
            mib_frame,
            textvariable=self.known_symbol_var,
            values=list(BUILTIN_SYMBOLS.keys()),
            state="readonly",
            width=24,
        )
        builtin_combo.grid(row=0, column=1, sticky="w", padx=5, pady=5)
        builtin_combo.bind("<<ComboboxSelected>>", self.apply_known_symbol)

        ttk.Label(mib_frame, text="Importeret symbol:").grid(row=0, column=2, sticky="w", padx=5, pady=5)
        self.imported_combo = ttk.Combobox(
            mib_frame,
            textvariable=self.imported_symbol_var,
            values=[],
            state="readonly",
            width=42,
        )
        self.imported_combo.grid(row=0, column=3, sticky="we", padx=5, pady=5)
        self.imported_combo.bind("<<ComboboxSelected>>", self.apply_imported_symbol)

        ttk.Label(mib_frame, text="OID / symbol:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(mib_frame, textvariable=self.custom_oid_var, width=72).grid(row=1, column=1, columnspan=3, sticky="we", padx=5, pady=5)
        ttk.Button(mib_frame, text="Aflæs valgt OID", command=self.read_custom_oid).grid(row=1, column=4, padx=8, pady=5)

        ttk.Label(mib_frame, text="MIB-fil:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(mib_frame, textvariable=self.mib_file_var, width=72).grid(row=2, column=1, columnspan=3, sticky="we", padx=5, pady=5)
        ttk.Button(mib_frame, text="Importér .mib", command=self.select_mib_file).grid(row=2, column=4, padx=8, pady=5)

        ttk.Label(mib_frame, textvariable=self.imported_count_var).grid(row=3, column=0, columnspan=5, sticky="w", padx=5, pady=(0, 5))
        ttk.Label(
            mib_frame,
            text="Importerede symboler læses automatisk ud af den valgte fil. Selve opslaget bruger filens mappe som lokal MIB-kilde.",
            foreground="gray",
        ).grid(row=4, column=0, columnspan=5, sticky="w", padx=5, pady=(0, 5))
        mib_frame.columnconfigure(3, weight=1)

        summary_frame = ttk.LabelFrame(main, text="Oversigt", padding=10)
        summary_frame.pack(fill="x", pady=(0, 10))

        self.summary_labels = {}
        fields = ["Systemnavn", "Beskrivelse", "Oppetid", "Kontakt", "Placering", "Antal interfaces"]
        for i, field in enumerate(fields):
            ttk.Label(summary_frame, text=f"{field}:", width=18).grid(row=i, column=0, sticky="w", padx=5, pady=3)
            var = tk.StringVar(value="-")
            ttk.Label(summary_frame, textvariable=var).grid(row=i, column=1, sticky="w", padx=5, pady=3)
            self.summary_labels[field] = var

        interfaces_frame = ttk.LabelFrame(main, text="Interfaces", padding=10)
        interfaces_frame.pack(fill="both", expand=True)

        columns = ("index", "name", "status", "in_octets", "out_octets")
        self.if_tree = ttk.Treeview(interfaces_frame, columns=columns, show="headings", height=18)
        self.if_tree.heading("index", text="IfIndex")
        self.if_tree.heading("name", text="Navn")
        self.if_tree.heading("status", text="Status")
        self.if_tree.heading("in_octets", text="InOctets")
        self.if_tree.heading("out_octets", text="OutOctets")
        self.if_tree.column("index", width=80, anchor="center")
        self.if_tree.column("name", width=280, anchor="w")
        self.if_tree.column("status", width=140, anchor="center")
        self.if_tree.column("in_octets", width=180, anchor="e")
        self.if_tree.column("out_octets", width=180, anchor="e")

        for status_name, color in STATUS_COLORS.items():
            self.if_tree.tag_configure(status_name, background=color)

        scrollbar = ttk.Scrollbar(interfaces_frame, orient="vertical", command=self.if_tree.yview)
        self.if_tree.configure(yscrollcommand=scrollbar.set)
        self.if_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        bottom = ttk.Frame(main)
        bottom.pack(fill="x", pady=(10, 0))
        self.status_var = tk.StringVar(value="Klar")
        ttk.Label(bottom, textvariable=self.status_var).pack(side="left")
        ttk.Button(bottom, text="Ryd interface-tabel", command=self.clear_interfaces).pack(side="right")

    def apply_known_symbol(self, _event=None):
        key = self.known_symbol_var.get()
        self.custom_oid_var.set(BUILTIN_SYMBOLS.get(key, ""))

    def apply_imported_symbol(self, _event=None):
        symbol = self.imported_symbol_var.get().strip()
        if symbol:
            self.custom_oid_var.set(symbol)

    def select_mib_file(self):
        path = filedialog.askopenfilename(
            title="Vælg MIB-fil",
            filetypes=[("MIB files", "*.mib *.txt *.my"), ("Alle filer", "*.*")],
        )
        if not path:
            return

        try:
            mib_manager.load_file(path)
            self.mib_file_var.set(path)
            imported_symbols = mib_manager.symbols
            self.imported_combo["values"] = imported_symbols

            if imported_symbols:
                self.imported_symbol_var.set(imported_symbols[0])
                self.custom_oid_var.set(imported_symbols[0])
            else:
                self.imported_symbol_var.set("")

            self.imported_count_var.set(
                f"Importeret modul: {mib_manager.module_name} | fundet {len(imported_symbols)} symboler"
            )
            self.status_var.set(f"MIB importeret: {os.path.basename(path)}")
        except Exception as exc:
            messagebox.showerror("MIB-fejl", str(exc))

    def validate_inputs(self):
        ip = self.ip_var.get().strip()
        community = self.community_var.get().strip()
        port_text = self.port_var.get().strip()

        if not ip:
            raise ValueError("Du skal angive en IP-adresse")
        if not community:
            raise ValueError("Du skal angive et community-navn")
        if not port_text.isdigit():
            raise ValueError("Port skal være et tal")

        mib_path = self.mib_file_var.get().strip()
        if mib_path:
            mib_manager.load_file(mib_path)

        return ip, community, int(port_text)

    def run_in_thread(self, target):
        threading.Thread(target=target, daemon=True).start()

    def clear_interfaces(self):
        for item in self.if_tree.get_children():
            self.if_tree.delete(item)
        self.status_var.set("Interface-tabel ryddet")

    def toggle_polling(self):
        if self.polling_var.get():
            self.status_var.set("Live polling aktiveret")
            self.schedule_polling(initial=True)
        else:
            if self.polling_job:
                self.root.after_cancel(self.polling_job)
                self.polling_job = None
            self.status_var.set("Live polling stoppet")

    def schedule_polling(self, initial=False):
        if not self.polling_var.get():
            return
        if initial:
            self.refresh_all()
        self.polling_job = self.root.after(5000, self.polling_tick)

    def polling_tick(self):
        if not self.polling_var.get():
            self.polling_job = None
            return
        self.refresh_all(reschedule=True)

    def refresh_all(self, reschedule=False):
        try:
            ip, community, port = self.validate_inputs()
        except Exception as exc:
            messagebox.showerror("Inputfejl", str(exc))
            self.polling_var.set(False)
            self.toggle_polling()
            return

        self.status_var.set("Aflæser router og interfaces...")

        def task():
            try:
                summary = asyncio.run(read_summary(ip, community, port))
                interfaces = asyncio.run(read_interfaces(ip, community, port))
                self.root.after(0, lambda: self._apply_refresh(summary, interfaces, reschedule))
            except Exception as exc:
                err = str(exc)
                self.root.after(0, lambda e=err: self._show_error(e, reschedule))

        self.run_in_thread(task)

    def _apply_refresh(self, summary, interfaces, reschedule):
        for key, value in summary.items():
            if key in self.summary_labels:
                self.summary_labels[key].set(value)

        for item in self.if_tree.get_children():
            self.if_tree.delete(item)

        for row in interfaces:
            tag = row["status"] if row["status"] in STATUS_COLORS else "unknown"
            self.if_tree.insert(
                "",
                "end",
                values=(row["index"], row["name"], row["status"], row["in_octets"], row["out_octets"]),
                tags=(tag,),
            )

        up_count = sum(1 for row in interfaces if row["status"] == "up")
        self.status_var.set(f"Opdateret: {len(interfaces)} interfaces, {up_count} oppe")

        if self.polling_var.get() and reschedule:
            self.polling_job = self.root.after(5000, self.polling_tick)

    def read_custom_oid(self):
        try:
            ip, community, port = self.validate_inputs()
            oid_text = self.custom_oid_var.get().strip()
            if not oid_text:
                raise ValueError("Du skal angive en OID eller et MIB-symbol")
        except Exception as exc:
            messagebox.showerror("Inputfejl", str(exc))
            return

        self.status_var.set("Aflæser valgt OID...")

        def task():
            try:
                name, value = asyncio.run(snmp_get(ip, community, port, oid_text))
                self.root.after(0, lambda: self._show_single_result(name, value))
            except Exception as exc:
                err = str(exc)
                self.root.after(0, lambda e=err: self._show_error(e, False))

        self.run_in_thread(task)

    def _show_single_result(self, name, value):
        messagebox.showinfo("OID-resultat", f"{name}\n\nVærdi: {value}")
        self.status_var.set("Valgt OID aflæst")

    def _show_error(self, text, reschedule):
        self.status_var.set("Fejl ved SNMP-aflæsning")
        messagebox.showerror("SNMP-fejl", text)
        if self.polling_var.get() and reschedule:
            self.polling_job = self.root.after(5000, self.polling_tick)


if __name__ == "__main__":
    root = tk.Tk()
    app = SNMPRouterGUI(root)
    root.mainloop()
