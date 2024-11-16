# -*- coding: utf-8 -*-
import json
import re
import datetime
from ghidra.program.model.symbol import SymbolType

class MyDomainObjectConsumer:
    """
        분석된 파일 기준으로 program getDomainObject 함수로 오브젝트를 가져오기 위해서
        첫번째 파라미터로 해당 인스턴스가 존재해야 하여 작성함

        Attributes:
            name (str): 아무개 이름
    """

    def __init__(self, name):
        self.name = name

    def get_name(self):
        return self.name

def get_function_set(programs):
        func_set = set()
        for program in programs:
            for func in program.getFunctionManager().getFunctions(True):
                    func_set.add(func)
        return func_set

def get_json(func_set):
    return [
            {
                "function": f.getName(),
                "address": str(f.getEntryPoint()),
                "file": f.getProgram().getDomainFile().getName(),
            } for f in func_set
        ]
def generate_output_file():
        # 현재 날짜와 시간 가져오기
        current_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        # 동적으로 파일명 설정
        return "result_{}.json".format(current_time)

def extract_function_addresses(programs):
    func_set =  get_function_set(programs)
    with open(generate_output_file(), "w") as f:
            json.dump(get_json(func_set), f, indent=4)

def get_all_programs(project_data):
    """
        프로젝트 데이터에서 모든 프로그램을 가져옴.

        Parameters:
            project_data (object): Ghidra 프로젝트 데이터 객체.

        Returns:
            list: 프로젝트 내 모든 프로그램 리스트.
    """
    root_folder = project_data.getRootFolder()
    program_files = root_folder.getFiles()
    programs = []
    consumer = MyDomainObjectConsumer("MyConsumer")
    for program_file in program_files:
        program = program_file.getDomainObject(consumer, False, False, None)
        programs.append(program)
    return programs

if __name__ == "__main__":
    state = getState()
    project = state.getProject()
    if project is None:
        print("No project is currently open. Exiting script.")
        exit(0)
    project_data = project.getProjectData()
    programs = get_all_programs(project_data)
    if not programs:
        print("No programs found in the current project. Exiting script.")
        exit(0)
    extract_function_addresses(programs)
