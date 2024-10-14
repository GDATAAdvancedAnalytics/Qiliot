import idc
import idaapi
import idautils
import json
import os

RESULT_PATH = os.path.join(os.path.expanduser("~"), "Desktop", "AcidRain_Result")
ABSOLUT_PATH = os.getenv("LOCALAPPDATA")
GREEN = 0xDDFADA
RED = 0xFCCCC4
WHITE = 0xFFFFFF


class Results:

    def __init__(self) -> None:
        self.len_result_addr = None
        self.len_address_of_sample = 0
        self.main_addresses = set()
        self.emu_main_addresses = set()
        self.all_addresses = set()
        self.emu_all_addresses = set()

    def collect_all_instructions(self) -> None:
        """
        Collects all instructions within the specified segments (".fini", ".text", ".init") of the binary.
        """
        segments_of_interest = [".fini", ".text", ".init"] # LOAD is not included
        for seg_ea in idautils.Segments():
            next_address = seg_ea
            seg_name = idc.get_segm_name(seg_ea)
            if seg_name in segments_of_interest:
                segm_end = idc.get_segm_end(seg_ea)
                while next_address <= segm_end:
                   if not (next_address in self.all_addresses):
                        if idaapi.ua_mnem(next_address)  is not None:
                            self.all_addresses.add(next_address)
                        next_address = idc.next_head(next_address, segm_end)

    def collect_emulated_instructions(self, emulated_instructions) -> None:
        '''
        Collects the addresses of emulated instructions from the provided list.
        '''
        if emulated_instructions:
            for address in emulated_instructions:
                add = int(address,16 )
                if not (add in self.emu_all_addresses):
                    if idaapi.ua_mnem(add) is not None:
                        self.emu_all_addresses.add(add)

    def collect_core_instrutions(self) -> None:
        '''
        Compares virtual addresses in ida vs. the addresses in results.json file.
        If the addresses from the result file are in the segment of the binary file in ida.
        self.emu_main_addresses will be extend of this address.
        '''
        # Define virtual address of AcidRain core without library functions.
        start_acid_rain = 0x00400310
        end_acid_rain = 0x00401740
        
        next_acidrain_address = start_acid_rain
        while next_acidrain_address <= end_acid_rain:
            if not next_acidrain_address in self.main_addresses:
                if idaapi.ua_mnem(next_acidrain_address)  is not None:
                    self.main_addresses.add(next_acidrain_address)
                
            next_acidrain_address = idc.next_head(next_acidrain_address)


    def collect_emulated_core_instructions(self, emulated_instructions) -> None:
        '''
        Collects the addresses of emulated instructions that are part of the core function.
        
        Args:
        emulated_instructions (list of str): A list of emulated instruction addresses in hexadecimal format.
        '''
        if emulated_instructions: 
            for address in emulated_instructions:
                add = int(address, 16)
                if add in self.main_addresses and (not add in self.emu_main_addresses):
                    self.emu_main_addresses.add(add)
            

    def mark_all_instructions_in_red(self):
        '''
        Sets every virtual address in red.
        '''
        for address in self.all_addresses:
            idc.set_color(address, idc.CIC_ITEM, RED)

    def mark_emulated_instructions_in_green(self):
        '''
        Sets every virtual address which where emulated in green.
        '''
        #Add known instructions and colored them in green
        for address in self.emu_all_addresses:
            if  address:
                idc.set_color(address, idc.CIC_ITEM, GREEN)


    def remove_mark_instructions(self):
        '''
        Remove color from virtual address and set it back to white.
        '''
        for seg_ea in self.all_addresses:
            idc.set_color(seg_ea, idc.CIC_ITEM, WHITE)
            seg_ea = idc.next_head(seg_ea)
            


#########################################################################
#################        Main functions         #########################
#########################################################################

    def resolve_results(self) -> None:
        '''
        Read the results file in AcidRain_Results folder and 
        generates main statistics and acidrain core statistics.
        '''
        self.collect_all_instructions()
        self.collect_core_instrutions()
        self.mark_all_instructions_in_red()

        for filename in os.listdir(RESULT_PATH):
            # Read all files in folder and collects results.
            with open(os.path.join(RESULT_PATH, filename), 'r') as file:
                data = json.load(file)
                emu_instrution_addresses = data["instruction_addresses"]
                self.collect_emulated_core_instructions(emu_instrution_addresses)
                self.collect_emulated_instructions(emu_instrution_addresses)

        self.mark_emulated_instructions_in_green()
                
        print(f"""
                ###########################################################################
                #################     Internal Qiliot Logging     #########################
                ###########################################################################

                Total number of Instructions in AcidRain core:                {len(self.main_addresses)}
                Total number of emulated Instructions of AcidRain core:       {len(self.emu_main_addresses)}
                Emulation covers of AcidRain Main:                            {(len(self.emu_main_addresses) / len(self.main_addresses)) * 100}%
                ############################################################################
                Total number of Instructions in AcidRain:                     {len(self.all_addresses)}
                Total number of emulated Instructions of AcidRain:            {len(self.emu_all_addresses)}
                Emulation covers of AcidRain Main:                            {(len(self.emu_all_addresses) / len(self.all_addresses)) * 100}%
            """)
        
    def hide_results(self) -> None:
        '''
        Return all colored instructions back to color white.
        '''
        self.collect_all_instructions()
        self.remove_mark_instructions()

    def debug(self) -> None:
        print("Debug")


#########################################################################
#################   Shortcut for seeing results     #####################
#########################################################################

def register_menu_action(action_name, action_desc, handler, hotkey = None):
    show_choosers_action = idaapi.action_desc_t(
      action_name,
      action_desc,
      handler,
      hotkey,
      None,
      -1)
    idaapi.register_action(show_choosers_action)
    idaapi.attach_action_to_menu(
        'Edit/Plugins/%s' % action_desc,
        action_name,
        idaapi.SETMENU_APP)

class CIdaMenuHandlerResultsResolver(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self):
        #results.resolve_results(here())
        print("Start showing results.")
        results = Results()
        results.resolve_results()

        return 1

    def update(self):
        return idaapi.AST_ENABLE_ALWAYS

register_menu_action("script:resolve_results", "ShowResults", CIdaMenuHandlerResultsResolver, "I") # I - for Show results

class CIdaMenuHandlerResultsHideResolver(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self):
        #results.resolve_results(here())
        print("Start hiding results.")
        results = Results()
        results.hide_results()

        return 1

    def update(self):
        return idaapi.AST_ENABLE_ALWAYS


register_menu_action("script:hide_results", "HideResults", CIdaMenuHandlerResultsHideResolver, "P") # P - for Hide(clear) results
