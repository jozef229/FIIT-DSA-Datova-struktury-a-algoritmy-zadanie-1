// zadanie1.c -- Jozef Varga, 5.10.2017 15:35

#include <stdio.h>
#include <string.h>

#define hlavicka_struktury (sizeof(struct bloky))
#define velkost_bloku (sizeof(unsigned int))
#define obsadenost_bloku (sizeof(char))
#define pata_bloku (velkost_bloku + obsadenost_bloku)

#include <stdio.h>
#include <string.h>

void *ukazovatel_na_pamat;

struct bloky{
    unsigned int velkost;
    struct bloky *po;
};

void set_pata_velkost(unsigned int *cesta, unsigned int velkost){
    *cesta = velkost;
}

void set_pata_obsadenost(char *cesta, char obsadenost){
    *cesta = obsadenost;
}

void memory_init(void *ptr, unsigned int size){
    struct bloky *inicializacia,*root;
    ukazovatel_na_pamat = ptr;
    root = (struct bloky*)ukazovatel_na_pamat;
    root->velkost = 0;
    inicializacia = (struct bloky*)(ukazovatel_na_pamat + hlavicka_struktury);
    inicializacia->velkost = (size - 2*hlavicka_struktury - pata_bloku - obsadenost_bloku);
    root->po = inicializacia;
    inicializacia->po = NULL;
    set_pata_velkost((unsigned int*)(ukazovatel_na_pamat + (size - obsadenost_bloku - pata_bloku)), inicializacia->velkost);
    set_pata_obsadenost((ukazovatel_na_pamat + (size - 2*obsadenost_bloku)), '0');
    set_pata_obsadenost((ukazovatel_na_pamat + (size - obsadenost_bloku)), '1');
}

void najvhodnejsi_blok(struct bloky **prve_volne, struct bloky **pred_prve_volne, unsigned int size){
    struct bloky *prehladaj, *pred_prehladaj;
    if((*prve_volne)->po != NULL)(*prve_volne) = (*prve_volne)->po;
    while ((*prve_volne)->velkost < size && (*prve_volne)->po != NULL ) {
        (*pred_prve_volne) = (*pred_prve_volne)->po;
        (*prve_volne) = (*prve_volne)->po;
    }
    pred_prehladaj = (*pred_prve_volne);
    prehladaj = (*prve_volne);
    while ((*prve_volne) != NULL ) {
        if((*prve_volne)->velkost < prehladaj->velkost && (*prve_volne)->velkost >= size ){
            pred_prehladaj = (*pred_prve_volne);
            prehladaj = (*prve_volne);
        }
        (*prve_volne) = (*prve_volne)->po;
        (*pred_prve_volne) = (*pred_prve_volne)->po;
    }
    (*pred_prve_volne) = pred_prehladaj;
    (*prve_volne) = prehladaj;
}

void *memory_alloc(unsigned int size){
    struct bloky *prve_volne, *pred_prve_volne, *uvolnene;
    char *ukazovatel_na_uvolnene, *pociatok_pamat;
    pred_prve_volne = ukazovatel_na_pamat;
    prve_volne = ukazovatel_na_pamat;
    najvhodnejsi_blok(&prve_volne, &pred_prve_volne, size);
    if(prve_volne->velkost >= size){
        if(prve_volne->velkost <= size + (2*hlavicka_struktury + 2*pata_bloku)){
            pociatok_pamat = (char*)prve_volne + hlavicka_struktury;
            pred_prve_volne->po = prve_volne->po;
            set_pata_obsadenost((char*)prve_volne + (hlavicka_struktury + prve_volne->velkost + velkost_bloku), '1');
            return pociatok_pamat;
        }
        else{
            pociatok_pamat = (char*)prve_volne + hlavicka_struktury;
            ukazovatel_na_uvolnene = (char*)prve_volne + (hlavicka_struktury + size + pata_bloku);
            uvolnene = (struct bloky*)ukazovatel_na_uvolnene;
            uvolnene->velkost = (prve_volne->velkost - size - hlavicka_struktury - pata_bloku);
            uvolnene->po = prve_volne->po;
            set_pata_obsadenost((char*)uvolnene - obsadenost_bloku, '1');
            set_pata_velkost((unsigned int*)((char*)uvolnene - pata_bloku), size);
            set_pata_velkost((unsigned int*)((char*)uvolnene + uvolnene->velkost + hlavicka_struktury), uvolnene->velkost);
            set_pata_obsadenost((char*)uvolnene + uvolnene->velkost + hlavicka_struktury + velkost_bloku, '0');
            pred_prve_volne->po = uvolnene;
            prve_volne->velkost = size ;
            return pociatok_pamat;
        }
    }
    else{
        return NULL;
    }
}

int memory_check(void *ptr){
    if(ptr == NULL )return 0;
    else return 1;
}

int memory_free(void *valid_ptr){
    if(!memory_check(valid_ptr)){
        return 1;
    }
    struct bloky *prava_strana, *root, *lava_strana, *poslany_blok;
    root = (struct bloky*)ukazovatel_na_pamat;
    char *ukazovatel_na_uvolnene;
    ukazovatel_na_uvolnene = valid_ptr - hlavicka_struktury - obsadenost_bloku ;
    if(*(char*)ukazovatel_na_uvolnene == '0'){
        ukazovatel_na_uvolnene = ukazovatel_na_uvolnene - velkost_bloku;
        ukazovatel_na_uvolnene -= *(unsigned int *)ukazovatel_na_uvolnene;
        ukazovatel_na_uvolnene -= hlavicka_struktury;
        lava_strana = (struct bloky*)ukazovatel_na_uvolnene;
        poslany_blok = (struct bloky*)(valid_ptr - hlavicka_struktury);
        lava_strana->velkost += (poslany_blok->velkost + hlavicka_struktury + pata_bloku);
        ukazovatel_na_uvolnene = (char*)lava_strana + lava_strana->velkost + hlavicka_struktury;
        *(unsigned int*)ukazovatel_na_uvolnene = lava_strana->velkost;
        ukazovatel_na_uvolnene += velkost_bloku;
        *(char*)ukazovatel_na_uvolnene = '0';
        ukazovatel_na_uvolnene += obsadenost_bloku;
        if(*(char*)ukazovatel_na_uvolnene != '1'){
            prava_strana = (struct bloky*)ukazovatel_na_uvolnene;
            ukazovatel_na_uvolnene += prava_strana->velkost + velkost_bloku + hlavicka_struktury;
            if(*ukazovatel_na_uvolnene == '0'){
                lava_strana->velkost += pata_bloku + prava_strana->velkost + hlavicka_struktury;
                struct bloky *pred_prava_strana;
                pred_prava_strana = ukazovatel_na_pamat;
                while (pred_prava_strana->po != prava_strana) pred_prava_strana = pred_prava_strana->po;
                pred_prava_strana->po = prava_strana->po;
                if(prava_strana->po == NULL) pred_prava_strana = NULL;
                ukazovatel_na_uvolnene -= velkost_bloku;
                *(unsigned int*) ukazovatel_na_uvolnene = lava_strana->velkost;
            }
        }
    }else {
        poslany_blok = (struct bloky*)(valid_ptr - hlavicka_struktury);
        ukazovatel_na_uvolnene = valid_ptr + pata_bloku + poslany_blok->velkost;
        if(*(char*)ukazovatel_na_uvolnene != '1'){
            prava_strana = (struct bloky*)ukazovatel_na_uvolnene;
            ukazovatel_na_uvolnene += hlavicka_struktury + prava_strana->velkost +velkost_bloku;
            if(*(char*)ukazovatel_na_uvolnene == '0'){
                ukazovatel_na_uvolnene -= velkost_bloku;
                poslany_blok->velkost += hlavicka_struktury + pata_bloku + prava_strana->velkost;
                poslany_blok->po = prava_strana->po;
                *(unsigned int*)ukazovatel_na_uvolnene = poslany_blok->velkost;
                struct bloky *pred_prava_strana;
                pred_prava_strana = ukazovatel_na_pamat;
                while (pred_prava_strana->po != prava_strana) pred_prava_strana = pred_prava_strana->po;
                pred_prava_strana->po = poslany_blok;
            }else {
                if(root->po != NULL){
                    poslany_blok->po = root->po;
                    root->po = poslany_blok;
                }
                else {
                    poslany_blok->po = NULL;
                    root->po = poslany_blok;
                }
                ukazovatel_na_uvolnene = valid_ptr + velkost_bloku + poslany_blok->velkost;
                *(char*)ukazovatel_na_uvolnene = '0';
            }
            
        }else {
            if(root->po != NULL){
                poslany_blok->po = root->po;
                root->po = poslany_blok;
            }
            else {
                poslany_blok->po = NULL;
                root->po = poslany_blok;
            }
            ukazovatel_na_uvolnene = valid_ptr + velkost_bloku + poslany_blok->velkost;
            *(char*)ukazovatel_na_uvolnene = '0';
        }
    }
    return 0;
}

// Vlastna funkcia main() je pre vase osobne testovanie. Dolezite: pri testovacich scenaroch sa nebude spustat!
int main()
{
    char region[50];
    memory_init(region, 50);
    char* pointer = (char*) memory_alloc(10);
    if (pointer)
        memset(pointer, 0, 10);
    if (pointer)
        memory_free(pointer);
    return 0;
}
