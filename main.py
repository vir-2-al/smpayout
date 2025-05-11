class CheckVariant(object):
    def __init__(self,
                 board_width: int = 0,
                 board_height: int = 0,
                 p_x: int = 0,
                 p_y: int = 0
                 ):

        self.board_width = board_width
        self.board_hight = board_height

        self.board = {
            (x, y): False
                for x in range(self.board_width)
                    for y in range(self.board_hight)
        }

        self.start_x = p_x
        self.start_y = p_y
        # self.board[self.start_x, self.start_y] = True
        return

    def IsComplete(self, board: dict) -> bool:
        return all(board.values())

    def IsValidMove(self, next_x: int, next_y: int):
        return next_x in range(self.board_width) and next_y in range(self.board_hight)

    def GetAllValidMove(self, x: int, y: int) -> list:
        all_pos = []
        var_1_x, var_1_y = x - 2, y + 1
        var_2_x, var_2_y = x - 2, y - 1
        var_3_x, var_3_y = x - 1, y - 2
        var_4_x, var_4_y = x - 1, y + 2
        var_5_x, var_5_y = x + 2, y - 1
        var_6_x, var_6_y = x + 2, y + 1
        var_7_x, var_7_y = x + 1, y - 2
        var_8_x, var_8_y = x + 1, y + 2
        if self.IsValidMove(var_1_x, var_1_y):
            all_pos.append((var_1_x, var_1_y))
        if self.IsValidMove(var_2_x, var_2_y):
            all_pos.append((var_2_x, var_2_y))
        if self.IsValidMove(var_3_x, var_3_y):
            all_pos.append((var_3_x, var_3_y))
        if self.IsValidMove(var_4_x, var_4_y):
            all_pos.append((var_4_x, var_4_y))
        if self.IsValidMove(var_5_x, var_5_y):
            all_pos.append((var_5_x, var_5_y))
        if self.IsValidMove(var_6_x, var_6_y):
            all_pos.append((var_6_x, var_6_y))
        if self.IsValidMove(var_7_x, var_7_y):
            all_pos.append((var_7_x, var_7_y))
        if self.IsValidMove(var_8_x, var_8_y):
            all_pos.append((var_8_x, var_8_y))
        return all_pos

    def GetCount(self, board: dict, next_x: int, next_y: int, cur_path: str = '') -> str:
        if self.board[next_x, next_y] == True:
            return cur_path
        self.board[next_x, next_y] = True
        cur_path += str(chr(ord('A')+next_x)+chr(ord('1')+next_y)+' ')

        for (x, y) in self.GetAllValidMove(next_x, next_y):
            var_path = self.GetCount(board=board, next_x=x, next_y=y, cur_path=cur_path)
            if len(var_path) > len(cur_path):
                cur_path = var_path
        return cur_path

    def CheckAllVariant(self):
        moves = self.GetCount(board=self.board, next_x=self.start_x, next_y=self.start_y, cur_path='')
        print(f'x: {self.start_x}, y: {self.start_y}, moves: {moves}')
        return moves

def main():
    board_width = 8
    board_height = 8
    max_moves = ''
    for c_y in range(board_height):
        for c_x in range(board_width):
            print(f'check variant start pos({c_y}, {c_x})')
            cur_var = CheckVariant(board_width, board_height, c_x, c_y)
            cur_moves = cur_var.CheckAllVariant()
            if len(cur_moves) > len(max_moves):
                max_moves = cur_moves
    print(f'max_moves: {max_moves}')


if __name__ == "__main__":
    main()