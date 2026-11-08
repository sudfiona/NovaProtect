#include <stdio.h>
__declspec(dllexport) int alpha_one(int x){ return x+1; }
__declspec(dllexport) int beta_two(int x){ return x*2; }
__declspec(dllexport) int gamma_three(int x){ return x-3; }
__declspec(dllexport) int delta_four(int x){ return x^4; }
int main(void){ printf("%d\n", alpha_one(1)+beta_two(2)+gamma_three(3)+delta_four(4)); return 0; }
