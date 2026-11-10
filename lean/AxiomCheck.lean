import Zui
/-! Headline theorems; `check.sh` fails if any of them depends on more than the standard
axioms (propext, Classical.choice, Quot.sound). -/
#print axioms Zui.Bcs.readUleb32_uleb
#print axioms Zui.Bcs.readUleb32_canonical
#print axioms Zui.Bcs.uleb_last_nonzero
#print axioms Zui.Bcs.dec_encode
#print axioms Zui.Bcs.dec_canonical
#print axioms Zui.Bcs.decodeFull_iff
#print axioms Zui.Bcs.encoding_unique
#print axioms Zui.Bcs.dec_consumed
#print axioms Zui.Gas.senderRebate_le
#print axioms Zui.Gas.computation_le_budget
#print axioms Zui.Gas.charge_le_budget
#print axioms Zui.Gas.outOfGas_summary
#print axioms Zui.Gas.charge_gasLeft_le
#print axioms Zui.Gas.le_halfDigits
#print axioms Zui.Gas.chargeList_batch
#print axioms Zui.Store.recover_crash
#print axioms Zui.Store.recover_idem
#print axioms Zui.Store.replay_idem
#print axioms Zui.Store.replay_from_snapshot
